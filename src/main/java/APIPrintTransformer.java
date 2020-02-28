import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import soot.Body;
import soot.PatchingChain;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.SootFieldRef;
import soot.SootField;
import soot.Unit;
import soot.ValueBox;
import soot.jimple.Stmt;
import soot.util.Chain;

public class APIPrintTransformer extends SceneTransformer
{
    /**
     * Print Android APIs
     */

    private String pkgName;
    private String outputPath;

    APIPrintTransformer(String pkgName, String outputPath) {
        this.pkgName = pkgName;
        this.outputPath = outputPath;
    }

    @Override
    protected void internalTransform(String phaseName, Map<String, String> options)
    {
        HashMap<String, List<String>> Dec2Invo = new HashMap<String, List<String>>();
        //(1) Obtain all application classes
        Chain<SootClass> sootClasses = Scene.v().getApplicationClasses();

        for (Iterator<SootClass> iter = sootClasses.snapshotIterator(); iter.hasNext();)
        {
            SootClass sc = iter.next();
            if (!isSelfClass(sc)){
                continue;
            }

            String scClassName = sc.getName();
            String scPackageNameName = sc.getPackageName();
            System.out.println(scClassName);

            //(2) Obtain all the methods from a given class
            List<SootMethod> sootMethods = sc.getMethods();

            for (int i = 0; i < sootMethods.size(); i++) {
                SootMethod sm = sootMethods.get(i);
                String callerSig = sm.getSignature();
                if (callerSig.equals("")){
                    continue;
                }
                List<String> InvoList = new ArrayList<String>();

                try {
                    Body body = sm.retrieveActiveBody();

                    //(3) Obtain all statements from a given method
                    PatchingChain<Unit> units = body.getUnits();

                    for (Iterator<Unit> unitIter = units.snapshotIterator(); unitIter.hasNext(); ) {
                        Stmt stmt = (Stmt) unitIter.next();

                        //(4) Check if the statement is related to method invocation
                        if (stmt.containsInvokeExpr()) {
                            SootMethod callee = stmt.getInvokeExpr().getMethod();
                            SootClass calleeClass = callee.getDeclaringClass();
                            String calleeClassName = calleeClass.getName();

                            // Add restrictions on the API being called
//                             if (calleeClassName.startsWith("")) {
//                                List<ValueBox> vbs2 = stmt.getUseAndDefBoxes();
//                                System.out.println(vbs2.get(0).getValue());
                                if (!sm.getSignature().contains("void <init>()") &&
                                        !callee.getSignature().contains("void <init>()")){

                                    String calleeSig = callee.getSignature();
                                    InvoList.add(calleeSig);
                                }
//                            }
                        }
                    }
                } catch (Exception ex) {
                    //TODO: No active body retrieved from the method
                }
                if (!InvoList.isEmpty()) {
                    Dec2Invo.put(callerSig, InvoList);
                }
            }
        }

        try {
            this.SaveDic(Dec2Invo);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void SaveDic(HashMap<String, List<String>> Dict) throws Exception{
        FileOutputStream fos = new FileOutputStream(this.outputPath);
        OutputStreamWriter osw = new OutputStreamWriter(fos, "utf-8");

        CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader("Declaration", "Invocations");
        CSVPrinter csvPrinter = new CSVPrinter(osw, csvFormat);

        for (Map.Entry<String, List<String>> entry : Dict.entrySet()) {
            System.out.println("Key = " + entry.getKey() + ", Value = " + entry.getValue());
            csvPrinter.printRecord(entry.getKey(), entry.getValue());
        }

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

}

