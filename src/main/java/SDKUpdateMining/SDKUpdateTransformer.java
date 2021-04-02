package SDKUpdateMining;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.IfStmt;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.manifest.ProcessManifest;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SDKUpdateTransformer extends BodyTransformer
{

    private String Sha256;
    private String pkgName;
    private String outputPath;
    private String outputSaveAPI;
    private  List<String> OldList = new ArrayList<>();
    private  List<String> NewList = new ArrayList<>();

    SDKUpdateTransformer(String appPath, String outputPath, String outputSaveAPI, String CDA_path) {
        this.pkgName = getPackageName(appPath);
        List<String> pathElements = new ArrayList<>();
        Paths.get(appPath).forEach(p -> pathElements.add(p.toString()));
        String s = pathElements.get(pathElements.size() - 1);
        this.Sha256 = s.substring(0, s.length() - 4);
        this.outputPath = outputPath;
        this.outputSaveAPI = outputSaveAPI;

        try {
            loadfromCDAFile(CDA_path);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected void internalTransform(final Body body, String phaseName, @SuppressWarnings("rawtypes") Map options) {
        final PatchingChain<Unit> units = body.getUnits();
        Value sdkValue = null;
        boolean flag_protected = false;

        for (Iterator<Unit> unitIter = units.snapshotIterator(); unitIter.hasNext(); ) {
            Stmt stmt = (Stmt) unitIter.next();

            if (stmt instanceof AssignStmt) {
//                            StaticFieldRef staticFieldRef = (StaticFieldRef) ((AssignStmt) stmt).getRightOp();
//                            Local local_var = (Local) ((AssignStmt) stmt).getLeftOp();
//                            StaticFieldRef ref = Jimple.v().newStaticFieldRef(Scene.v().
//                                    getField("<android.os.Build$VERSION: int SDK_INT>").makeRef());
                AssignStmt as = (AssignStmt) stmt;
                if (as.toString().contains("android.os.Build$VERSION: int SDK_INT")) {
                    sdkValue = as.getLeftOp();
                } else {
                    if (as.getLeftOp().equivTo(sdkValue)) {  // if SDK_INT var is redefined.
                        sdkValue = null;
                    }
                }
                continue;
            }

            if (stmt instanceof IfStmt && null != sdkValue) {

                IfStmt ifStmt = (IfStmt) stmt;
                List<ValueBox> bv = ifStmt.getCondition().getUseBoxes();

//                if (ifStmt.getTarget() instanceof ReturnStmt) {
//                    continue;
//                }

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

                flag_protected = true;
                // step in a new one
                String case_ = "";
                boolean flag_old = false;
                boolean flag_new = false;
                String API_old = null;
                String API_new = null;

                // if it is the comparison: if $i0 < 16 goto return, go on to detect if SEA exists
                while (unitIter.hasNext()) {
                    Stmt s = (Stmt) unitIter.next();

                    if (s instanceof AssignStmt) {    // if encounter a new assignment to the SDK_INT var, break the while loop
                        AssignStmt as1 = (AssignStmt) s;
                        if (as1.getLeftOp().equivTo(sdkValue)) {
                            // the last if - else ends
                            if (flag_old && API_new == null && API_old != null  && !flag_new ) {
                                try {
                                    case_ = "only old";
                                    if (SaveResults(body.getMethod().getSignature(), API_old, "None", case_)) {
                                        System.out.println("Results saving error!");
                                    }
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                            } else if (flag_new && API_old == null && API_new != null && !flag_old) {
                                try {
                                    case_ = "only new";
                                    if (SaveResults(body.getMethod().getSignature(), "None", API_new, case_)) {
                                        System.out.println("Results saving error!");
                                    }
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                            }
                            break;
                        }
                    }

                    if (s.containsInvokeExpr()) {
                        SootMethod callee = s.getInvokeExpr().getMethod();
                        String calleeSig = callee.getSignature();
                        if (this.OldList.contains(calleeSig)) {
                            flag_old = true;
                            API_old = calleeSig;
                        } else if (this.NewList.contains(calleeSig)){ // now is new, then find the old one
                            flag_new = true;
                            API_new = calleeSig;
                        }
                    }

                    if (flag_old && flag_new && API_old != null && API_new != null) {
                        // find all, break the while loop
                        try {
                            case_ = "both old and new";
                            if (SaveResults(body.getMethod().getSignature(), API_old, API_new, case_)) {
                                System.out.println("Results saving error!");
                            }
                            flag_old = flag_new = false;
                            API_old = API_new = null;
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        break;
                    }

                }

                if (!unitIter.hasNext() && !case_.equals("both old and new")) {
                    if (flag_old && API_old != null) {
                        try {
                            case_ = "only old";
                            if (SaveResults(body.getMethod().getSignature(), API_old, "None", case_)) {
                                System.out.println("Results saving error!");
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    } else if (flag_new && API_new != null) {
                        try {
                            case_ = "only new";
                            if (SaveResults(body.getMethod().getSignature(), "None", API_new, case_)) {
                                System.out.println("Results saving error!");
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }

            if (!flag_protected && stmt.containsInvokeExpr()){
                SootMethod callee = stmt.getInvokeExpr().getMethod();
                String calleeSig = callee.getSignature();
                if (this.OldList.contains(calleeSig)) {
                    try {
                        if (SaveResults(body.getMethod().getSignature(), calleeSig, "None", "none protected old")) {
                            System.out.println("Results saving error!");
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } else if (this.NewList.contains(calleeSig)) {
                    try {
                        if (SaveResults(body.getMethod().getSignature(), "None", calleeSig, "none protected new")) {
                            System.out.println("Results saving error!");
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }




    private void SaveDic(HashMap<String, List<String>> Dict) throws Exception{
        FileOutputStream fos = new FileOutputStream(this.outputPath);
        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);

        CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader("MethodSig", "FirstInvoke");
        CSVPrinter csvPrinter = new CSVPrinter(osw, csvFormat);

        for (Map.Entry<String, List<String>> entry : Dict.entrySet()) {
            System.out.println("MethodSig = " + entry.getKey() + ", FirstInvoke = " + entry.getValue());
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

    private void loadfromCDAFile(String CDApath) throws IOException {
        this.OldList.add("<TakePlace>");
        this.NewList.add("<TakePlace>");
        File filename = new File(CDApath); // 要读取以上路径的input.txt文件
        InputStreamReader reader = new InputStreamReader(
                new FileInputStream(filename)); // 建立一个输入流对象reader
        BufferedReader br = new BufferedReader(reader); // 建立一个对象，它把文件内容转成计算机能读懂的语言
        String line = "";
        line = br.readLine();
        while (line != null) {
            // (14)<android.widget.RemoteViews: void setRemoteAdapter(int,int,android.content.Intent)>[normal]    ---->    <android.widget.RemoteViews: void setRemoteAdapter(int,android.content.Intent)>[normal]
            Pattern pattern = Pattern.compile("\\S+(<\\S+:\\s\\S+\\s[\\w<>]+\\(.*\\)>)[\\s\\S]+----> {1,10}(<\\S+:\\s\\S+\\s[\\w<>]+\\(.*\\)>)[\\s\\S]+");
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                String old_sig = matcher.group(1);
                String new_sig = matcher.group(2);
                this.OldList.add(old_sig);
                this.NewList.add(new_sig);
            }
            line = br.readLine(); // 一次读入一行数据
        }
        System.out.println(this.OldList.size());
    }

    private boolean SaveResults(String methodSig, String old_API, String new_API, String case_) throws IOException {
        String fold_subname;
        if (old_API.equals("None")){
            fold_subname = Integer.toString(this.NewList.indexOf(new_API));
        } else {
            fold_subname = Integer.toString(this.OldList.indexOf(old_API));
        }
        Path dir_path = Paths.get(outputSaveAPI, fold_subname);
        if (CheckandMkdir(dir_path.toString())){
            File file = new File(dir_path.toString(), Sha256 + ".txt");
            FileWriter fileWritter = new FileWriter(file,true);
            BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
            bufferWritter.write(methodSig);
            bufferWritter.write("\n");
            bufferWritter.close();

            FileOutputStream fos = new FileOutputStream(outputPath, true);
            OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
            // CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader("Old_API", "Method_Signature");
            CSVFormat csvFormat = CSVFormat.DEFAULT;
            CSVPrinter csvPrinter = new CSVPrinter(osw, csvFormat);

            System.out.println("case_ = " + case_+ ", Old_API = " + old_API + ", New_API = " + new_API + ", Method_Signature = " + methodSig);
            csvPrinter.printRecord(case_, old_API, new_API, methodSig);

            csvPrinter.flush();
            csvPrinter.close();

            return false;

        } else {
            return true;
        }
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
