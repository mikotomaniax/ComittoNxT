package src.comitton.common;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
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

public class SmbFileAccess {
    private SmbFile sfile = null;

    public SmbFile authSmbFile( String url, String user, String pass ) throws MalformedURLException, CIFSException {
        boolean change = true;

        if( sfile != null ){
            URL next_url = new URL( url );
            if( sfile.getLocator().getURL().getHost().equals( next_url.getHost() ) ) {
                if( user != null && user.length() > 0 ) {
                    if( sfile.getLocator().getURL().getUserInfo().equals( user + ":" + pass ) ){
                        // 同一のサーバーアクセス
                        change = false;
                    }
                }else{
                    // 同一のサーバーアクセス
                    change = false;
                }
            }
        }

        if( change ) {
            if (user != null && user.length() > 0) {
                Properties prop = new Properties();
                prop.put("jcifs.smb.client.minVersion", DialectVersion.SMB1);       // SMB1は切らない(SMB2に対応していればそちらで繋がるので)
                prop.put("jcifs.smb.client.maxVersion", DialectVersion.SMB311);     // 恐らく内部的にはSMB210辺りまでしか対応していないっぽい？
                prop.put( "jcifs.smb.client.strictResourceLifecycle", "true" );		    // false
                Configuration config = new PropertyConfiguration(prop);
                CIFSContext baseContext = new BaseContext(config);
                CIFSContext contextWithCred = baseContext.withCredentials(new NtlmPasswordAuthentication(baseContext, "", user, pass));
                sfile = new SmbFile(url, contextWithCred);
            } else {
                Properties prop = new Properties();
                prop.put("jcifs.smb.client.minVersion", DialectVersion.SMB1);        // SMB1は切らない(SMB2に対応していればそちらで繋がるので)
                prop.put("jcifs.smb.client.maxVersion", DialectVersion.SMB1);        // 匿名アクセスはSMB1しか許可されていない
                prop.put("jcifs.smb.client.useExtendedSecurity", "false");        // 匿名アクセスはセキュリティを切らないと利用出来ない
                Configuration config = new PropertyConfiguration(prop);
                CIFSContext baseContext = new BaseContext(config);
                CIFSContext contextWithCred = baseContext.withGuestCrendentials();
                sfile = new SmbFile(url, contextWithCred);
            }
        }else{
            sfile = new SmbFile( url, sfile.getContext() );
        }

        return sfile;
    }

    public String[] getSmbFileList( String url, String user, String pass ) throws MalformedURLException, CIFSException {
        boolean change = true;

        if( sfile != null ){
            URL next_url = new URL( url );
            if( sfile.getLocator().getURL().getHost().equals( next_url.getHost() ) ) {
                if( user != null && user.length() > 0 ) {
                    if( sfile.getLocator().getURL().getUserInfo().equals( user + ":" + pass ) ){
                        // 同一のサーバーアクセス
                        change = false;
                    }
                }else{
                    // 同一のサーバーアクセス
                    change = false;
                }
            }
        }

        if( change ) {
            if( user != null && user.length() > 0 ){
                Properties prop = new Properties();
                prop.put( "jcifs.smb.client.minVersion", DialectVersion.SMB1 );		// SMB1は切らない(SMB2に対応していればそちらで繋がるので)
                prop.put( "jcifs.smb.client.maxVersion", DialectVersion.SMB311 );	// 恐らく内部的にはSMB210辺りまでしか対応していないっぽい？
                Configuration config = new PropertyConfiguration(prop);
                CIFSContext baseContext = new BaseContext(config);
                CIFSContext contextWithCred = baseContext.withCredentials(new NtlmPasswordAuthentication(baseContext,"", user, pass));
                sfile = new SmbFile(url, contextWithCred);
            }else{
                Properties prop = new Properties();
                prop.put( "jcifs.smb.client.minVersion", DialectVersion.SMB1 );		// SMB1は切らない(SMB2に対応していればそちらで繋がるので)
                prop.put( "jcifs.smb.client.maxVersion", DialectVersion.SMB1 );		// 匿名アクセスはSMB1しか許可されていない
                prop.put( "jcifs.smb.client.useExtendedSecurity", "false" );		// 匿名アクセスはセキュリティを切らないと利用出来ない
                Configuration config = new PropertyConfiguration(prop);
                CIFSContext baseContext = new BaseContext(config);
                CIFSContext contextWithCred = baseContext.withGuestCrendentials();
                sfile = new SmbFile(url, contextWithCred);
            }
        }else{
            sfile = new SmbFile( url, sfile.getContext() );
        }

        String[] list = sfile.list();

    //    sfile.close();
    //    sfile = null;

        return list;
    }

    public SmbFile authSmbFile( String url ) throws MalformedURLException, CIFSException {
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

    public SmbFileInputStream authSmbFileInputStream( String url, String user, String pass ) throws MalformedURLException, SmbException, UnknownHostException, CIFSException {
        SmbFileInputStream stream;

        if (user != null && user.length() > 0) {
            SmbFile sfile = authSmbFile(url, user, pass);
            stream = new SmbFileInputStream(sfile);
        } else {
            //stream = new SmbFileInputStream(url);
            SmbFile sfile = authSmbFile(url, "", "");
            stream = new SmbFileInputStream(sfile);
        }

        return stream;
    }
}
