package src.comitton.dialog;

import java.io.File;
import java.util.EventListener;

import src.comitton.common.FileAccess;

import jcifs.smb.SmbFile;
import jp.dip.muracoro.comittont.R;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnDismissListener;
import android.graphics.drawable.PaintDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.Display;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class RemoveDialog extends Dialog implements Runnable, Handler.Callback, OnClickListener, OnDismissListener {
	public static final int MSG_MESSAGE = 1;
	public static final int MSG_ERRMSG = 2;

	private RemoveListener mListener = null;

	private String mFullPath;
	private String mUser;
	private String mPass;
	private String mItem;
	private Thread mThread;
	private boolean mBreak;
	private Handler mHandler;
	private Context mContext;

	private TextView mMsgText;
	private Button mBtnCancel;
	private boolean mIsLocal;

	public RemoveDialog(Context context, String uri, String path, String user, String pass, String item, RemoveListener removeListener) {
		super(context);
		Window dlgWindow = getWindow();

		// 画面をスリープ有効
		dlgWindow.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

		// タイトルなし
		requestWindowFeature(Window.FEATURE_NO_TITLE);

		// Activityを暗くしない
		dlgWindow.setFlags(0 , WindowManager.LayoutParams.FLAG_DIM_BEHIND);

		// 背景を透明に
		PaintDrawable paintDrawable = new PaintDrawable(0xC0000000);
		dlgWindow.setBackgroundDrawable(paintDrawable);

		setCanceledOnTouchOutside(false);
		setOnDismissListener(this);

		mListener = removeListener;
		mContext = context.getApplicationContext();

		if (uri == null || uri.length() == 0) {
			mIsLocal = true;
		}
		else {
			mIsLocal = false;
		}
		mFullPath = uri + path;
		mUser = user;
		mPass = pass;
		mItem = item;
		mBreak = false;

		mHandler = new Handler(this);
		return;
	}

	protected void onCreate(Bundle savedInstanceState){
		super.onCreate(savedInstanceState);

		WindowManager wm = (WindowManager)mContext.getSystemService(Context.WINDOW_SERVICE);
		// ディスプレイのインスタンス生成
		Display disp = wm.getDefaultDisplay();
		int cx = disp.getWidth();
		int cy = disp.getHeight();
		int width = Math.min(cx, cy);

		setContentView(R.layout.removedialog);

		mMsgText = (TextView)this.findViewById(R.id.text_msg);
		mMsgText.setWidth(width);
		mBtnCancel  = (Button)this.findViewById(R.id.btn_cancel);

		// キャンセル
		mBtnCancel.setOnClickListener(this);

		mThread = new Thread(this);
		mThread.start();
	}

	public void run() {
		// コピー開始
		try {
			if (mIsLocal == true) {
				localRemoveFile("", mItem);
			}
			else {
				smbRemoveFile("", mItem);
			}
		}
		catch (Exception e) {
			String msg;
			if (e != null && e.getMessage() != null) {
				msg = e.getMessage();
			}
			else {
				msg = "File Access Error.";
			}
			sendMessage(MSG_ERRMSG, msg, 0, 0);
		}
		// プログレス終了
		this.dismiss();
	}

	public boolean localRemoveFile(String path, String item) throws Exception {
		File file = new File(mFullPath + path + item);
		if (file.isDirectory()) {
			// 再帰呼び出し
			String nextpath = path + item;
			File sfile = new File(mFullPath + nextpath);
			File[] sfiles = null;

			sfiles = sfile.listFiles();
			int filenum = sfiles.length;
			if (sfiles != null && filenum > 0) {
				// ファイルあり
				// ディレクトリ内のファイル
				for (int i = 0; i < filenum; i++) {
					String name = sfiles[i].getName();
					if (name.equals("..")) {
						continue;
					}
					localRemoveFile(nextpath, name);
					if (mBreak) {
						// 中断
						break;
					}
				}
			}
			file.delete();
		}
		else {
			// 削除ファイル表示
			sendMessage(MSG_MESSAGE, path + item, 0, 0);

			// ファイル削除
			File localFile = new File(mFullPath + path + item);
			if (localFile.exists()) {
				localFile.delete();
			}
		}
		return true;
	}

	public boolean smbRemoveFile(String path, String item) throws Exception {
		SmbFile file = FileAccess.authSmbFile(mFullPath + path + item, mUser, mPass);
		if (file.isDirectory()) {
			// 再帰呼び出し
			String nextpath = path + item;
			SmbFile sfile = FileAccess.authSmbFile(mFullPath + nextpath, mUser, mPass);
			SmbFile[] sfiles = null;

			sfiles = sfile.listFiles();
			int filenum = sfiles.length;
			if (sfiles == null || filenum <= 0) {
				// ファイルなし
				return true;
			}
			// ディレクトリ内のファイル
			for (int i = 0; i < filenum; i++) {
				String name = sfiles[i].getName();
				if (name.equals("..")) {
					continue;
				}
				smbRemoveFile(nextpath, name);
				if (mBreak) {
					// 中断
					break;
				}
			}
			file.delete();
		}
		else {
			// 削除ファイル表示
			sendMessage(MSG_MESSAGE, path + item, 0, 0);

			// ファイル削除
			SmbFile sambaFile = FileAccess.authSmbFile(mFullPath + path + item, mUser, mPass);
			if (sambaFile.exists()) {
				sambaFile.delete();
			}
		}
		return true;
	}

	private void sendMessage(int msg_id, String obj, int arg1, int arg2) {
		Message message = new Message();
		message.what = msg_id;
		message.arg1 = arg1;
		message.arg2 = arg2;
		message.obj = obj;
		mHandler.sendMessage(message);
	}

	public boolean handleMessage(Message msg) {
		// 受信
		switch (msg.what) {
			case MSG_MESSAGE:
				mMsgText.setText((String) msg.obj);
				return true;
			case MSG_ERRMSG:
				String msgstr = (String)msg.obj;
				Toast.makeText(mContext, msgstr, Toast.LENGTH_LONG).show();
				return true;
		}
		return false;
	}

	@Override
	public void onClick(View v) {
		// キャンセルクリック
		dismiss();
	}

	@Override
	public void onDismiss(DialogInterface dialog) {
		// 画面をスリープ有効
		getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
		mBreak = true;
		mListener.onClose();
	}

	public interface RemoveListener extends EventListener {
	    // 終了通知
	    public void onClose();
	}
}
