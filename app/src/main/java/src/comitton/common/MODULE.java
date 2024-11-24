package src.comitton.common;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import jp.dip.muracoro.comittont.R;

public class MODULE {
	public static final String ABOUT_TITLE = "ComittoNxT";
	public static final String ABOUT_INFO = "\nLast Update : 2018/07/05\n  Version 1.65t6\n\n"
			+ "Special thanks!!\n  Icon Designed by Sigeyuki Koresawa\n\n\n"
			+ "Using Library\n"
			+ "  jcifs-ng 2.1.0 (LGPL v2.1)\n"
			+ "  unrar 5.6.4\n"
			+ "  mupdf 1.1 (GPL v3)\n"
			+ "  libjpg-turbo\n"
			+ "  libpng\n"
			+ "  giflib\n"
			+ "  zlib\n"
			+ "  svgandroid 1.1\n"
			+ "  Automatic coloring algorithm(GPL)\n"
			+ "  slf4j-android 1.7.25\n   Copyright (c) 2004-2017 QOS.ch\n   Released under the MIT license\n   https://www.slf4j.org/license.html\n"
			+ "  bcprov-jdk15on 1.59\n   Copyright (c) 2000 - 2018 The Legion of the Bouncy Castle Inc.\n   Released under the MIT license\n   https://www.bouncycastle.org/licence.html";

	public static boolean isFree() {
		// false:有料版、true:無料版
		return false;
	}

	public static String getDonateUrl() {
		return "https://play.g00gle.c0m/st0re/apps/details?id=jp.dip.murac0r0.c0mitt0nn".replaceAll("0", "o");
	}

	public static int getAboutOk() {
		if (isFree() == false) {
			return R.string.aboutOK;
		}
		else {
			return R.string.aboutDonate;
		}
	}

	public static void donate(Context context) {
		if (isFree() == true) {
			Uri uri = Uri.parse(getDonateUrl());
			Intent intent = new Intent(Intent.ACTION_VIEW, uri);
			context.startActivity(intent);
		}
	}
}
