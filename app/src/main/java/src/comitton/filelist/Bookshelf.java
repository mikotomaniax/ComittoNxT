package src.comitton.filelist;

import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.Properties;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.DialectVersion;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;

public class Bookshelf {
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
				}
				else {
					user = userpass;
					pass = "";
				}
			}
		}
		return authSmbFile(url, user, pass);
	}

	// ユーザ認証付きSambaアクセス
	public static SmbFile authSmbFile(String url, String user, String pass) throws MalformedURLException {
		SmbFile sfile;
		Properties prop = new Properties();
		//prop.put( "jcifs.smb.client.enableSMB2", "true");
		//prop.put( "jcifs.smb.client.disableSMB1", "false");
		try{
		if (user != null && user.length() > 0) {
				//NtlmPasswordAuthentication npa = new NtlmPasswordAuthentication("", user, pass);
				//sfile = new SmbFile(url, npa);
				prop.put( "jcifs.smb.client.minVersion", DialectVersion.SMB1 );		// SMB1は切らない(SMB2に対応していればそちらで繋がるので)
				prop.put( "jcifs.smb.client.maxVersion", DialectVersion.SMB311 );	// 恐らく内部的にはSMB210辺りまでしか対応していないっぽい？
		//		prop.put( "jcifs.traceResources", "true" );
				Configuration config = new PropertyConfiguration(prop);
				CIFSContext baseContext = new BaseContext(config);
				CIFSContext contextWithCred = baseContext.withCredentials(new NtlmPasswordAuthentication(baseContext, "", user, pass));
				sfile = new SmbFile(url, contextWithCred);
		}
		else {
				//sfile = new SmbFile(url);
				prop.put( "jcifs.smb.client.minVersion", DialectVersion.SMB1 );		// SMB1は切らない(SMB2に対応していればそちらで繋がるので)
				prop.put( "jcifs.smb.client.maxVersion", DialectVersion.SMB1 );		// 匿名アクセスはSMB1しか許可されていない
		//		prop.put( "jcifs.traceResources", "true" );
				prop.put( "jcifs.smb.client.useExtendedSecurity", "false" );		// 匿名アクセスはセキュリティを切らないと利用出来ない
				Configuration config = new PropertyConfiguration(prop);
				CIFSContext baseContext = new BaseContext(config);
				CIFSContext contextWithCred = baseContext.withGuestCrendentials();
				sfile = new SmbFile(url, contextWithCred);
			}
		}catch(CIFSException e){
			//
			sfile = null;
		}
		return sfile;
	}

	// ユーザ認証付きSambaストリーム
	public static SmbFileInputStream authSmbFileInputStream(String url, String user, String pass) throws MalformedURLException, SmbException, UnknownHostException {
		SmbFileInputStream stream;
		if (user != null && user.length() > 0) {
			SmbFile sfile = authSmbFile(url, user, pass);
			stream = new SmbFileInputStream(sfile);
		}
		else {
			//stream = new SmbFileInputStream(url);
			SmbFile sfile = authSmbFile(url, "", "");
			stream = new SmbFileInputStream(sfile);
		}
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
}
