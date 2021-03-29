import Helper.ApplicationClassFilter;
import Helper.cgHelper;
import Model.BranchUnit;
import Model.UnitInfo;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.IfStmt;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.toolkits.graph.DirectedGraph;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class FindIfElseAPITransformer extends BodyTransformer
{

    private String Sha256;
    private String pkgName;
    private String outputPath;
    private JimpleBasedInterproceduralCFG iCfg;

    FindIfElseAPITransformer(String appPath, String outputPath, JimpleBasedInterproceduralCFG iCfg) {
        this.pkgName = getPackageName(appPath);
        List<String> pathElements = new ArrayList<>();
        Paths.get(appPath).forEach(p -> pathElements.add(p.toString()));
        String s = pathElements.get(pathElements.size() - 1);
        this.Sha256 = s.substring(0, s.length() - 4);
        this.outputPath = outputPath;
        this.iCfg = iCfg;
    }

    protected void internalTransform(final Body body, String phaseName, @SuppressWarnings("rawtypes") Map options) {
        SootMethod sm = body.getMethod();

        DirectedGraph<Unit> ug = this.iCfg.getOrCreateUnitGraph(sm.retrieveActiveBody());

        Iterator<Unit> uit = ug.iterator();
        List<Unit> units = new ArrayList<>();
        uit.forEachRemaining(units::add);

        for (int i = 0; i < units.size(); i++) {
            Unit u = units.get(i);
            if (u.branches()) {
                //If-ELSE Stmt
                if (u instanceof IfStmt) {
                    IfStmt uStmt = (IfStmt) u;
                    BranchUnit branchUnit = new BranchUnit();
                    branchUnit.declareMethod = sm;
                    branchUnit.branchInvokeUnit = u;

                    //Extract IF_ELSE branch invocation expressions separately
                    extractBranchAPIs(ug, u, sm, branchUnit);

                    // save branchUnit
                    try {
                        if (! branchUnit.ifBranchInvokeMethodList.isEmpty())
                            SaveBranchUnit(branchUnit);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
            }
        }
    }

    private static void extractBranchAPIs(DirectedGraph<Unit> ug, Unit u, SootMethod method, BranchUnit branchUnit) {
        List<Unit> list = ug.getSuccsOf(u);
        List<Unit> realList = list.stream().filter(s -> !s.toString().contains("@caughtexception")).collect(Collectors.toList());

        if (realList.size() == 1) {
            //If Branch
            Stmt ifStmt = (Stmt) realList.get(0);
            List<UnitInfo> ifUnits = getAllBranchStmts(ug, method, ifStmt);
            branchUnit.ifBranchInvokeMethods = ifUnits;
            branchUnit.ifBranchInvokeMethodList = ifUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());
        } else if (realList.size() > 1) {
            //If Branch
            Stmt ifStmt = (Stmt) realList.get(0);
            List<UnitInfo> ifUnits = getAllBranchStmts(ug, method, ifStmt);
            branchUnit.ifBranchInvokeMethods = ifUnits;
            branchUnit.ifBranchInvokeMethodList = ifUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());

            //ELSE Branch
            Stmt elseStmt = (Stmt) realList.get(1);
            List<UnitInfo> elseUnits = getAllBranchStmts(ug, method, elseStmt);
            branchUnit.elseBranchInvokeMethods = elseUnits;
            branchUnit.elseBranchInvokeMethodList = elseUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());
        }
    }

    private static List<UnitInfo> getAllBranchStmts(DirectedGraph<Unit> ug, SootMethod method, Stmt originStmt) {
        List<Stmt> allElseBranchStmt = findBranchStmts(originStmt, ug, new HashSet<>());
        List<UnitInfo> allUnits = new ArrayList<>();
        for (Stmt elseBranchStmt : allElseBranchStmt) {
            if (elseBranchStmt.containsInvokeExpr() && !ApplicationClassFilter.isClassSystemPackage(convert2PatternMethod(elseBranchStmt.toString()))
            ) {
                allUnits.addAll(cgHelper.collectInvokeAPIs(elseBranchStmt, method));
            } else {
                UnitInfo unitInfo = new UnitInfo(elseBranchStmt, method.getSignature());
                allUnits.add(unitInfo);
            }
        }
        return allUnits;
    }

    private static String convert2PatternMethod(String s) {
        Pattern pattern = Pattern.compile("(<.*>)", Pattern.DOTALL);
        Matcher matcher = pattern.matcher(s);
        if (matcher.find()) {
            return matcher.group(1);

        }
        return s;
    }


    private static List<Stmt> findBranchStmts(Stmt originStmt, DirectedGraph<Unit> ug, Set<Unit> visitedNodes) {
        List<Stmt> branchStmts = new ArrayList<>();

        if(visitedNodes.contains(originStmt)){
            return branchStmts;
        }
        visitedNodes.add(originStmt);

        List<Unit> nodes = ug.getSuccsOf(originStmt);

        List<Unit> realNodes = nodes.stream().filter(s -> !s.toString().contains("@caughtexception")).collect(Collectors.toList());

        if (realNodes.size() == 0) {
            branchStmts.add(originStmt);
            return branchStmts;
        }
        if (realNodes.size() == 1) {
            branchStmts.add(originStmt);
            branchStmts.addAll(findBranchStmts((Stmt) realNodes.get(0), ug, visitedNodes));
        }
        return branchStmts;
    }


    private void SaveBranchUnit(BranchUnit branchUnit) throws Exception{
        FileOutputStream fos = new FileOutputStream(this.outputPath);
        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);

        CSVFormat csvFormat = CSVFormat.DEFAULT;
        CSVPrinter csvPrinter = new CSVPrinter(osw, csvFormat);

        System.out.println("MethodSig = " + branchUnit.declareMethod.toString() +
                ", IfStmt = " + branchUnit.branchInvokeUnit.toString());

        csvPrinter.printRecord(branchUnit.declareMethod.toString(), branchUnit.branchInvokeUnit.toString(),
                String.join("|", branchUnit.ifBranchInvokeMethodList));

        csvPrinter.flush();
        csvPrinter.close();
    }

    private boolean isSelfClass(SootClass sootClass)
    {
        if (sootClass.isPhantom())
        {
            return false;
        }

        String packageName = sootClass.getPackageName();

        return packageName.startsWith(this.pkgName);
    }

    public static String getPackageName(String apkPath) {
        String packageName = "";
        try {
            ProcessManifest manifest = new ProcessManifest(apkPath);
            packageName = manifest.getPackageName();
        } catch (IOException | XmlPullParserException e) {
            e.printStackTrace();
        }
        return packageName;
    }

    private boolean CheckandMkdir(String path){
        File folder = new File(path);
        if (!folder.exists() && !folder.isDirectory()) {
            if (!folder.mkdir()) {
                System.out.println("Dir create error!");
                return false;
            }
        }
        return true;
    }

}
