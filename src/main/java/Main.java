import org.xmlpull.v1.XmlPullParserException;
import soot.G;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;


public class Main
{
    /**
     * args[0]: path of an apk
     * args[1]: pkg name of APK
     * args[2]: path of the dir of android jars
     * args[3] == OutputPath
     *
     * cd ~/testenv
     * git clone https://github.com/lilicoding/android-platforms
     *
     * args[1] == ~/testenv/android-platforms
     *
     */

//    public static List<String> excludePackagesList = new ArrayList<String>();

    public static void main(String[] args)
    {
        String appPath = args[0];
        String pkgName = args[1];
        String androidJars = args[2];
        String outputPath = args[3];

        String[] arguments =
                {
                        "-process-dir", appPath,
                        "-android-jars", androidJars,
                        "-ire",
                        "-pp",
                        "-allow-phantom-refs",
                        "-w",
                        "-p", "cg", "enabled:false"
                };

        G.reset();

//        excludePackagesList.add("java.");
//        excludePackagesList.add("android.");
//        excludePackagesList.add("javax.");
//        excludePackagesList.add("android.support.");
//        excludePackagesList.add("androidx.");
//        excludePackagesList.add("com.google.");


        APIPrintTransformer transformer = new APIPrintTransformer(pkgName, outputPath);

        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_output_format(Options.output_format_none);
        PackManager.v().getPack("wjtp").add(new Transform("wjtp.MethodFeatureTransformer", transformer));

        soot.Main.main(arguments);
    }


}
