package src.comitton.common;

import android.util.Log;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Properties;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.Credentials;
import jcifs.DialectVersion;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.JAASAuthenticator;
import src.comitton.exception.FileAccessException;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;

public class FileAccess {
	// ユーザ認証付きSambaアクセス
	public static SmbFile authSmbFile(String url) throws MalformedURLException {
		String user = null;
		String pass = null;

		// パラメタチェック
		if (url.indexOf("smb://") == 0) {
			int idx = url.indexOf("@");
			if (idx >= 0) {
				String userpass = url.substring(6, idx);
				idx = userpass.indexOf(":");
				if (idx >= 0) {
					user = userpass.substring(0, idx);
					user = URLDecoder.decode(user);
					pass = userpass.substring(idx + 1);
					pass = URLDecoder.decode(pass);
				} else {
					user = userpass;
					pass = "";
				}
			}
		}
		Log.d("jcifs-ng", "authSmbFile");
		return authSmbFile(url, user, pass);
	}

	private static boolean mSMB2use = false;

	public static boolean isSMB2() {
		return mSMB2use;
	}

	// ユーザ認証付きSambaアクセス
	public static SmbFile authSmbFile(String url, String user, String pass) throws MalformedURLException {
		SmbFile sfile = null;
		Properties prop = new Properties();
		// 2.0 > 2.1 で非推奨になったため変更
		//prop.put( "jcifs.smb.client.enableSMB2", "true");
		//prop.put( "jcifs.smb.client.disableSMB1", "false");
		try {
			if (user != null && user.length() > 0) {
				prop.put("jcifs.smb.client.minVersion", DialectVersion.SMB1);        // SMB1は切らない(SMB2に対応していればそちらで繋がるので)
				prop.put("jcifs.smb.client.maxVersion", DialectVersion.SMB311);    // 恐らく内部的にはSMB210辺りまでしか対応していないっぽい？
				//prop.put( "jcifs.smb.client.port139.enabled", "true" );				// false
				//prop.put( "jcifs.smb.useRawNTLM", "true" );							// false
				//prop.put( "jcifs.smb.client.disableSpnegoIntegrity", "true" );		// false
				//prop.put( "jcifs.smb.client.useSMB2Negotiation", "true" );			// false
				//prop.put( "jcifs.smb.client.useNTSmbs", "false" );					// true
				//prop.put( "jcifs.smb.client.signingPreferred", "true" );			// false
				//prop.put( "jcifs.smb.client.useNtStatus", "false" );				// true
				//prop.put( "jcifs.smb.client.strictResourceLifecycle", "true" );			// false
				//prop.put( "jcifs.smb.client.useBatching", "false" );					// true
				//		prop.put( "jcifs.traceResources", "true" );
				Configuration config = new PropertyConfiguration(prop);
				CIFSContext baseContext = new BaseContext(config);
				//NtlmPasswordAuthentication npa = new NtlmPasswordAuthentication("", user, pass);
				//sfile = new SmbFile(url, npa);
				// NtlmPasswordAuthentication も非推奨だが何に置き換えれば良いのか・・・
				CIFSContext contextWithCred = baseContext.withCredentials(new NtlmPasswordAuthentication(baseContext, "", user, pass));
				sfile = new SmbFile(url, contextWithCred);
				contextWithCred.close();
				baseContext.close();
			} else {
				//sfile = new SmbFile(url);
				prop.put("jcifs.smb.client.minVersion", DialectVersion.SMB1);        // SMB1は切らない(SMB2に対応していればそちらで繋がるので)
				prop.put("jcifs.smb.client.maxVersion", DialectVersion.SMB1);        // 匿名アクセスはSMB1しか許可されていない
				//		prop.put( "jcifs.traceResources", "true" );
				prop.put("jcifs.smb.client.useExtendedSecurity", "false");        // 匿名アクセスはセキュリティを切らないと利用出来ない
				Configuration config = new PropertyConfiguration(prop);
				CIFSContext baseContext = new BaseContext(config);
				CIFSContext contextWithCred = baseContext.withGuestCrendentials();
				sfile = new SmbFile(url, contextWithCred);
				Log.d("authSmbFile", "guest access " + url);
			}
		} catch (CIFSException e) {
			//
			sfile = null;
			Log.e("authSmbFile", "error");
		}
		Log.d("jcifs-ng", "authSmbFile");
		return sfile;
	}

	// ユーザ認証付きSambaストリーム
	public static SmbFileInputStream authSmbFileInputStream(String url, String user, String pass) throws MalformedURLException, SmbException, UnknownHostException {
		SmbFileInputStream stream;
		if (user != null && user.length() > 0) {
			SmbFile sfile = authSmbFile(url, user, pass);
			stream = new SmbFileInputStream(sfile);
		} else {
			//stream = new SmbFileInputStream(url);
			SmbFile sfile = authSmbFile(url, "", "");
			stream = new SmbFileInputStream(sfile);
		}
		Log.d("jcifs-ng", "authSmbFileInputStream");
		return stream;
	}

	public static String createUrl(String url, String user, String pass) {
		if (url == null) {
			return "";
		}
		if (url.length() <= 6) {
			return url;
		}
		if (url.substring(0, 6).equals("smb://") == false || user == null || user.length() == 0) {
			return url;
		}
		// サーバ名
		String ret = "smb://" + URLEncoder.encode(user);
		if (pass != null && pass.length() > 0) {
			ret += ":" + URLEncoder.encode(pass);
		}
		ret += "@" + url.substring(6);
		return ret;
	}

	public static String getInnerFile(String uri, String path, String user, String pass) {
		boolean isLocal;

		File lfiles[] = null;
		SmbFile sfile = null;
		SmbFile[] sfiles = null;

		if (uri == null || uri.length() == 0) {
			isLocal = true;
		} else {
			isLocal = false;
		}

		if (isLocal) {
			// ローカルの場合のファイル一覧取得
			lfiles = new File(path).listFiles();
			if (lfiles == null) {
				return null;
			}
		} else {
			// サーバの場合のファイル一覧取得
			try {
				sfile = FileAccess.authSmbFile(uri + path, user, pass);
			} catch (MalformedURLException e) {
				// 
			}
			try {
				sfiles = sfile.listFiles();
			} catch (SmbException e) {
				// 
			}
			if (sfiles == null) {
				return null;
			}
		}

		int length;
		if (isLocal) {
			length = lfiles.length;
		} else {
			length = sfiles.length;
		}

		ArrayList<String> list = new ArrayList<String>(length);
		String name;
		boolean flag;
		for (int i = 0; i < length; i++) {
			if (isLocal) {
				name = lfiles[i].getName();
				flag = lfiles[i].isDirectory();
			} else {
				name = sfiles[i].getName();
				int len = name.length();
				if (name != null && len >= 1 && name.substring(len - 1).equals("/")) {
					flag = true;
				} else {
					flag = false;
				}
			}

			if (!flag) {
				// 通常のファイル
				String ext = DEF.getExtension(name);
				if (ext.equals(".jpg") || ext.equals(".jpeg") || ext.equals(".png") || ext.equals(".gif")/* || ext.equals(".bmp")*/
						|| ext.equals(".zip") || ext.equals(".rar") || ext.equals(".cbz") || ext.equals(".cbr") || ext.equals(".pdf") || ext.equals(".epub")) {
					list.add(name);
				}
			}
		}
		if (list.size() > 0) {
			Collections.sort(list);
			return list.get(0);
		}
		return null;
	}

	public static boolean renameTo(String uri, String path, String fromfile, String tofile, String user, String pass) throws FileAccessException {
		if (tofile.indexOf('/') > 0) {
			throw new FileAccessException("Invalid file name.");
		}

		if (uri == null || uri.length() == 0) {
			// サーバの場合のファイル一覧取得
			File orgfile = new File(path + fromfile);
			if (orgfile.exists() == false) {
				// 変更前ファイルが存在しなければエラー
				throw new FileAccessException("File not found.");
			}
			File dstfile = new File(path + tofile);
			if (dstfile.exists() == true) {
				// 変更後ファイルが存在すればエラー
				throw new FileAccessException("File access error.");
			}

			orgfile.renameTo(dstfile);
		} else {
			// サーバの場合のファイル一覧取得
			SmbFile orgfile;
			try {
				orgfile = FileAccess.authSmbFile(uri + path + fromfile, user, pass);
				if (orgfile.exists() == false) {
					// 変更前ファイルが存在しなければエラー
					throw new FileAccessException("File not found.");
				}
			} catch (MalformedURLException e) {
				throw new FileAccessException(e);
			} catch (SmbException e) {
				throw new FileAccessException(e);
			}

			SmbFile dstfile;
			try {
				dstfile = FileAccess.authSmbFile(uri + path + tofile, user, pass);
				if (dstfile.exists() == true) {
					// 変更後ファイルが存在すればエラー
					throw new FileAccessException("File access error.");
				}
			} catch (MalformedURLException e) {
				throw new FileAccessException(e);
			} catch (SmbException e) {
				throw new FileAccessException(e);
			}

			// ファイル名変更
			try {
				orgfile.renameTo(dstfile);
			} catch (SmbException e) {
				throw new FileAccessException(e);
			}
		}
		return true;
	}

	// ファイル存在チェック
	public static boolean exist(String uri, String path, String file, String user, String pass) throws FileAccessException {
		boolean result;
		if (uri == null || uri.length() == 0) {
			// ローカルの場合
			File orgfile = new File(path + file);
			result = orgfile.exists();
		} else {
			// サーバの場合
			SmbFile orgfile;
			try {
				orgfile = FileAccess.authSmbFile(uri + path + file, user, pass);
			} catch (MalformedURLException e) {
				throw new FileAccessException(e);
			}
			try {
				result = orgfile.exists();
			} catch (SmbException e) {
				throw new FileAccessException(e);
			}
		}
		return result;
	}

	// ファイル削除
	public static boolean delete(String uri, String path, String file, String user, String pass) throws FileAccessException {
		boolean result;
		if (uri == null || uri.length() == 0) {
			// ローカルの場合
			File orgfile = new File(path + file);
			orgfile.delete();
			result = orgfile.exists();
		} else {
			// サーバの場合
			SmbFile orgfile;
			try {
				orgfile = FileAccess.authSmbFile(uri + path + file, user, pass);
			} catch (MalformedURLException e) {
				throw new FileAccessException(e);
			}
			try {
				orgfile.delete();
				result = orgfile.exists();
			} catch (SmbException e) {
				throw new FileAccessException(e);
			}
		}
		return result;
	}
}
