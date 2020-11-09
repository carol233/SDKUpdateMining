package edu.monash.apkscan;

import soot.options.Options;

import java.io.File;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SEAInstrument {
	public static final String TAG = "Pei";
	
	public void ApkInstrument(String apkPath, String seasFilePath, String output_dir, String androidJars, int apiLevel) {
		G.reset();
		
		String[] args =
        {
			"-process-dir", apkPath,
            "-ire",
			"-pp",
			"-keep-line-number",
			"-allow-phantom-refs",
			"-w",
			"-p", "cg", "enabled:false",
			"-src-prec", "apk",
			"-process-multiple-dex"
        };
		
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_output_format(Options.output_format_dex);
		Options.v().set_output_dir(output_dir);
		if (-1 != apiLevel)
			Options.v().set_force_android_jar(androidJars + File.separator + "android-" + apiLevel + File.separator + "android.jar");
		else
			Options.v().set_android_jars(androidJars);
		
		Scene.v().addBasicClass("java.io.PrintStream",SootClass.SIGNATURES);
		Scene.v().addBasicClass("java.lang.System",SootClass.SIGNATURES);

		PackManager.v().getPack("jtp").add(new Transform("jtp.myLogger", new BodyTransformer() {

			@Override
			protected void internalTransform(final Body b, String phaseName, 
					@SuppressWarnings("rawtypes") Map options) {
				final PatchingChain<Unit> units = b.getUnits();
				Set<String> seas = CommonUtils.loadFile(seasFilePath);
				Value sdkValue = null;
				Stmt sdkStmt = null;
				for (Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
					final Unit u = (Unit) iter.next();
					Stmt stmt = (Stmt) u;
					if (stmt instanceof AssignStmt) {
						AssignStmt as = (AssignStmt) stmt;
						if (stmt.toString().contains("VERSION: int SDK_INT")) {   // find the definition of SDK_INT:  $i0 = <android.os.Build$VERSION: int SDK_INT>
							sdkValue = as.getLeftOp();
							sdkStmt = stmt;
//							System.out.println(stmt.toString());
						} else {
							if (as.getLeftOp().equivTo(sdkValue)) {  // if SDK_INT var is redefined.
								sdkValue = null;
								sdkStmt = null;
							}
						}
					}
					if (stmt instanceof IfStmt && null != sdkValue) {
//						System.out.println(stmt.toString());
						IfStmt ifStmt = (IfStmt) stmt;
						List<ValueBox> bv = ifStmt.getCondition().getUseBoxes();
						if (bv.size() != 2) {     // check if the stmt is the SDK_INT compare: if $i0 < 16 goto return
							continue;
						} else {
							if (bv.get(0).getValue().equivTo((sdkValue))) {
								if (!bv.get(1).getValue().toString().chars().allMatch( Character::isDigit ) ||
										bv.get(1).getValue().toString().equals("null") ||
										bv.get(1).getValue().toString().equals("0")) {
									continue;
								}
							} else if (bv.get(1).getValue().equivTo(sdkValue)) {
								if (!bv.get(0).getValue().toString().chars().allMatch( Character::isDigit ) ||
										bv.get(0).getValue().toString().equals("null") ||
										bv.get(0).getValue().toString().equals("0")) {
									continue;
								}
							} else {
								continue;
							}
						}
						// if it is the comparison: if $i0 < 16 goto return, go on to detect if SEA exists
//						System.out.println(stmt.toString());
						while (iter.hasNext()) {
							Unit innerU = (Unit) iter.next();
							Stmt s = (Stmt) innerU;
//							System.out.println(s.toString());

							if (s instanceof AssignStmt) {    // if encounter a new assignment to the SDK_INT var, break the while loop
								AssignStmt as = (AssignStmt) s;
								if (as.getLeftOp().equivTo(sdkValue)) {
									break;
								}
							}
							if (s.equals(ifStmt.getTarget())) {  // get to the if stmt target, break the while loop
								break;
							} else {
								String sea = containSEA(s, seas);
								if (!sea.isEmpty()) {
									System.out.println(stmt.toString() + "%" + sea); // here find a SEA
								}
							}
						}
					}
				}
			}
		}));
		soot.Main.main(args);
	}
	
	private static Local addTmpRef(Body body)
	{
	    Local tmpRef = Jimple.v().newLocal("tmpRef", RefType.v("java.io.PrintStream"));
	    body.getLocals().add(tmpRef);
	    return tmpRef;
	}

	private static Local addTmpString(Body body)
	{
	    Local tmpString = Jimple.v().newLocal("tmpString", RefType.v("java.lang.String")); 
	    body.getLocals().add(tmpString);
	    return tmpString;
	}

	private static Local addRetTmpString(Body body)
	{
	    Local tmpString = Jimple.v().newLocal("retTmpString", RefType.v("java.lang.String")); 
	    body.getLocals().add(tmpString);
	    return tmpString;
	}

	private static boolean isReturnVoid(String methodSig) {
		boolean retVoid = false;
		String[] splits = methodSig.split(" ");
		if (splits[1].equals("void")) {
			retVoid = true;
		}
		return retVoid;
	}
	
	private static Local appendTwoString(Body b, Value s1, Value s2, List<Unit> generated) {
		SootClass builderClass = Scene.v().getSootClass("java.lang.StringBuilder");
		RefType builderType = builderClass.getType();
		
		NewExpr newBuilderExpr = Jimple.v().newNewExpr(builderType);
		
		Local builderLocal = Jimple.v().newLocal("builderLocal", builderType);
		
		generated.add(Jimple.v().newAssignStmt(builderLocal, newBuilderExpr));
		
		b.getLocals().add(builderLocal);
		
		Local tmpBuilderLocal = Jimple.v().newLocal("tmpBuilderLocal", builderType);
		
		b.getLocals().add(tmpBuilderLocal);
		
		Local resultLocal = Jimple.v().newLocal("resultLocal", RefType.v("java.lang.String"));
		b.getLocals().add(resultLocal);
		
		VirtualInvokeExpr appendExpr = Jimple.v().newVirtualInvokeExpr(builderLocal, 
				builderClass.getMethod("java.lang.StringBuilder append(java.lang.String)").makeRef(), s2);
		VirtualInvokeExpr toStrExpr = Jimple.v().newVirtualInvokeExpr(builderLocal, 
				builderClass.getMethod("java.lang.String toString()").makeRef());
		
		generated.add(Jimple.v().newInvokeStmt(
				Jimple.v().newSpecialInvokeExpr(builderLocal, builderClass.getMethod("void <init>(java.lang.String)").makeRef(), s1)));
		generated.add(Jimple.v().newAssignStmt(tmpBuilderLocal, appendExpr));
		generated.add(Jimple.v().newAssignStmt(resultLocal,  toStrExpr));
		
		return resultLocal;
	}

	private static String containSEA(Stmt s, Set<String> seas) {
		if (s.containsInvokeExpr()) {
			InvokeExpr invokeExpr = s.getInvokeExpr();
			String methodSig = invokeExpr.getMethod().getSignature();
			String simplifiedMethodSig = CommonUtils.extractSimplifiedMethodSig(methodSig);
			if (seas.contains(simplifiedMethodSig)) {
				return simplifiedMethodSig;
			}
		}
		return "";
	}
}