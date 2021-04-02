package SDKUpdateMining;

import Helper.ApplicationClassFilter;
import Helper.cgHelper;
import Model.BranchUnit;
import Model.UnitInfo;
import edu.anonymous.GlobalRef;
import edu.anonymous.help.EntryPointHelper;
import edu.psu.cse.siis.coal.AnalysisParameters;
import edu.psu.cse.siis.coal.PropagationIcfg;
import edu.psu.cse.siis.coal.arguments.ArgumentValueManager;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.IfStmt;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.toolkits.graph.DirectedGraph;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class Main {
    public static void main(String[] args) throws FileNotFoundException {
        // 11A9EBD9C663CA920D4A3F94A9304431A5AE94F37E35A7802A41801FE0F99FD2.apk /Users/yzha0544/Library/Android/sdk/platforms output.csv
        String appPath = args[0];
        String androidJars = args[1];
        String outputPath = args[2];

        JimpleBasedInterproceduralCFG iCfg = initialize(appPath, androidJars + "/android-28/android.jar");

        hiddenSensitiveBranchAnalysis(iCfg, outputPath);
    }

    private static void hiddenSensitiveBranchAnalysis(JimpleBasedInterproceduralCFG iCfg, String outputPath) {
        Scene.v().getApplicationClasses().forEach(aClass -> {

            aClass.getMethods().stream().filter(am -> am.isConcrete()
                    && !ApplicationClassFilter.isClassInSystemPackage(am.getDeclaringClass().getName())
                    && !am.getSignature().contains("dummyMainClass")).forEach(targetMethod -> {
                DirectedGraph<Unit> ug = iCfg.getOrCreateUnitGraph(targetMethod.retrieveActiveBody());
                Iterator<Unit> uit = ug.iterator();
                List<Unit> units = new ArrayList<>();
                uit.forEachRemaining(units::add);

                Value sdkValue = null;

                for (int i = 0; i < units.size(); i++) {
                    Unit u = units.get(i);
                    SootMethod method = AnalysisParameters.v().getIcfg().getMethodOf(u);
                    if (method == null) {
                        continue;
                    }

                    //If-ELSE Stmt
                    if (u instanceof AssignStmt) {
                        AssignStmt as = (AssignStmt) u;
                        if (as.toString().contains("android.os.Build$VERSION: int SDK_INT")) {
                            sdkValue = as.getLeftOp();
                        } else {
                            if (as.getLeftOp().equivTo(sdkValue)) {  // if SDK_INT var is redefined.
                                sdkValue = null;
                            }
                        }
                    }

                    else if (u instanceof IfStmt && null != sdkValue) {
                        IfStmt uStmt = (IfStmt) u;
                        List<ValueBox> bv = uStmt.getCondition().getUseBoxes();

                        if (bv.size() != 2) {     // check if the stmt is the SDK_INT compare: if $i0 < 16 goto return
                            continue;
                        } else {
                            if (bv.get(0).getValue().equivTo((sdkValue))) {
                                if (!bv.get(1).getValue().toString().chars().allMatch(Character::isDigit) ||
                                        bv.get(1).getValue().toString().equals("null") ||
                                        bv.get(1).getValue().toString().equals("0")) {
                                    continue;
                                }
                            } else if (bv.get(1).getValue().equivTo(sdkValue)) {
                                if (!bv.get(0).getValue().toString().chars().allMatch(Character::isDigit) ||
                                        bv.get(0).getValue().toString().equals("null") ||
                                        bv.get(0).getValue().toString().equals("0")) {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }

                        BranchUnit branchUnit = new BranchUnit();
                        branchUnit.declareMethod = targetMethod;
                        branchUnit.branchInvokeUnit = u;

                        //Extract IF_ELSE branch invocation expressions separately
                        extractBranchAPIs(ug, u, method, branchUnit);

                        // save branchUnit
                        try {
                            if (!branchUnit.ifBranchUnitList.isEmpty())
                                SaveBranchUnit(branchUnit, outputPath);
                            sdkValue = null;
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                    }
                }
            });
        });
    }

    private static void extractBranchAPIs(DirectedGraph<Unit> ug, Unit u, SootMethod method, BranchUnit branchUnit) {
        List<Unit> list = ug.getSuccsOf(u);
        List<Unit> realList = list.stream().filter(s -> !s.toString().contains("@caughtexception")).collect(Collectors.toList());

        if (realList.size() == 1) {
            //If Branch
            Stmt ifStmt = (Stmt) realList.get(0);
            List<UnitInfo> allUnits = getAllBranchUnits(ug, method, ifStmt);
            List<UnitInfo> invokeUnits = getAllBranchInvokeStmts(ug, method, ifStmt);
            branchUnit.ifBranchUnits = allUnits;
            branchUnit.ifBranchUnitList = allUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());
            branchUnit.ifBranchInvokeMethods = invokeUnits;
            branchUnit.ifBranchInvokeMethodList = invokeUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());
        } else if (realList.size() > 1) {
            //If Branch
            Stmt ifStmt = (Stmt) realList.get(0);
            List<UnitInfo> allUnits = getAllBranchUnits(ug, method, ifStmt);
            List<UnitInfo> invokeUnits = getAllBranchInvokeStmts(ug, method, ifStmt);
            branchUnit.ifBranchUnits = allUnits;
            branchUnit.ifBranchUnitList = allUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());
            branchUnit.ifBranchInvokeMethods = invokeUnits;
            branchUnit.ifBranchInvokeMethodList = invokeUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());

            //ELSE Branch
            Stmt elseStmt = (Stmt) realList.get(1);
            List<UnitInfo> elseUnits = getAllBranchUnits(ug, method, elseStmt);
            List<UnitInfo> elseinvokeUnits = getAllBranchInvokeStmts(ug, method, elseStmt);
            branchUnit.elseBranchUnits = elseUnits;
            branchUnit.elseBranchUnitList = elseUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());
            branchUnit.elseBranchInvokeMethods = elseinvokeUnits;
            branchUnit.elseBranchInvokeMethodList = elseinvokeUnits.stream().map(unit -> unit.getUnit().toString()).collect(Collectors.toList());
        }
    }

    private static List<UnitInfo> getAllBranchUnits(DirectedGraph<Unit> ug, SootMethod method, Stmt originStmt) {
        List<Stmt> allElseBranchStmt = findBranchStmts(originStmt, ug, new HashSet<>());
        List<UnitInfo> allUnits = new ArrayList<>();
        for (Stmt elseBranchStmt : allElseBranchStmt) {
            if (elseBranchStmt.containsInvokeExpr()
                // && !ApplicationClassFilter.isClassSystemPackage(convert2PatternMethod(elseBranchStmt.toString()))
            ) {
                allUnits.addAll(cgHelper.collectInvokeAPIs(elseBranchStmt, method));
            } else {
                UnitInfo unitInfo = new UnitInfo(elseBranchStmt, method.getSignature());
                allUnits.add(unitInfo);
            }
        }
        return allUnits;
    }

    private static List<UnitInfo> getAllBranchInvokeStmts(DirectedGraph<Unit> ug, SootMethod method, Stmt originStmt) {
        List<Stmt> allElseBranchStmt = findBranchStmts(originStmt, ug, new HashSet<>());
        List<UnitInfo> allUnits = new ArrayList<>();
        for (Stmt elseBranchStmt : allElseBranchStmt) {
            if (elseBranchStmt.containsInvokeExpr()) {
                allUnits.addAll(cgHelper.collectInvokeAPIs(elseBranchStmt, method));
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


    private static void SaveBranchUnit(BranchUnit branchUnit, String outputPath) throws Exception{
        FileOutputStream fos = new FileOutputStream(outputPath, true);
        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);

        CSVFormat csvFormat = CSVFormat.DEFAULT;
        CSVPrinter csvPrinter = new CSVPrinter(osw, csvFormat);

        csvPrinter.printRecord(branchUnit.declareMethod.toString(), branchUnit.branchInvokeUnit.toString(),
                String.join("|", branchUnit.ifBranchInvokeMethodList),
                String.join("|", branchUnit.elseBranchInvokeMethodList),
                String.join("|", branchUnit.ifBranchUnitList),
                String.join("|", branchUnit.elseBranchUnitList));

        csvPrinter.flush();
        csvPrinter.close();
    }

    private static JimpleBasedInterproceduralCFG initialize(String apkPath, String forceAndroidJar) throws FileNotFoundException {
        //calculate EntryPoint to generate dummyMainMethod
        init(apkPath, forceAndroidJar);
        System.out.println(apkPath);

        // Initialize Soot
        SetupApplication analyser = new SetupApplication(forceAndroidJar, apkPath);
        analyser.constructCallgraph();

        JimpleBasedInterproceduralCFG iCfg = new PropagationIcfg();
        AnalysisParameters.v().setIcfg(iCfg);
        ArgumentValueManager.v().registerDefaultArgumentValueAnalyses();

        GlobalRef.iCfg = iCfg;
        return iCfg;
    }

    public static void init(String apkPath, String forceAndroidJar) {
        try {
            EntryPointHelper.calculateEntryPoint(apkPath, forceAndroidJar);
        } catch (IOException | XmlPullParserException e) {
            e.printStackTrace();
            System.out.println("==>calculateEntryPoint error:" + e);
        }
    }


}