import soot.G;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;


public class Main
{
    /**
     *
     * cd ~/testenv
     * git clone https://github.com/lilicoding/android-platforms
     *
     * args[1] == ~/testenv/android-platforms
     *
     */

    public static void main(String[] args)
    {
        String appPath = args[0];
        String androidJars = args[1];
        String CDA_path= args[2];
        String outputPath = args[3];
        String outputSaveAPI = args[4];

        String[] arguments =
                {
                        "-process-dir", appPath,
                        "-android-jars", androidJars,
                        "-ire",
                        "-pp",
                        "-allow-phantom-refs",
                        "-w",
                        "-p", "cg", "enabled:false",
                        "-process-multiple-dex"
                };

        G.reset();


        SDKUpdateTransformer transformer = new SDKUpdateTransformer(appPath, outputPath, outputSaveAPI, CDA_path);

        Options.v().set_src_prec(Options.src_prec_apk);
        // Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_output_format(Options.output_format_none);
        PackManager.v().getPack("jtp").add(new Transform("jtp.SDKUpdateTransformer", transformer));

        soot.Main.main(arguments);

    }

}