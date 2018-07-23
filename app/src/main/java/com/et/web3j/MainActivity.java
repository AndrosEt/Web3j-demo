package com.et.web3j;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Handler;
import android.support.annotation.RequiresApi;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.et.web3j.util.SecureRandomUtils;
import com.et.web3j.web3jdemo.R;
import com.orhanobut.logger.AndroidLogAdapter;
import com.orhanobut.logger.Logger;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.wallet.DeterministicSeed;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Wallet;
import org.web3j.crypto.WalletFile;
import org.web3j.crypto.WalletUtils;
import org.web3j.utils.Numeric;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private Button btCreate, btImport;
    private EditText etMnemonic;

    private final String password = "test1011";
    /**
     * 通用的以太坊基于bip44协议的助记词路径 （imtoken jaxx Metamask myetherwallet）
     */
    public static String ETH_JAXX_TYPE = "m/44'/60'/0'/0/0";
    public static String ETH_LEDGER_TYPE = "m/44'/60'/0'/0";
    public static String ETH_CUSTOM_TYPE = "m/44'/60'/1'/0/0";

    /**
     * 随机
     */
    private static final SecureRandom secureRandom = SecureRandomUtils.secureRandom();

    public static final int REQUEST_CODE_EXTERNAL = 1;

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
        initPermission();
    }

    /**
     * check the permission
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private void initPermission() {
        Logger.addLogAdapter(new AndroidLogAdapter() {
            @Override
            public boolean isLoggable(int priority, String tag) {
                return true;
            }
        });

        if(!(ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED)) {
            requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQUEST_CODE_EXTERNAL);
        }
    }

    /**
     * get the result from user action
     * @param requestCode
     * @param permissions
     * @param grantResults
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, @android.support.annotation.NonNull String[] permissions, @android.support.annotation.NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode) {
            case REQUEST_CODE_EXTERNAL:
                if (!(grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED)) {    // 权限申请成功
                    Toast.makeText(MainActivity.this, "Write storage permissions are required", Toast.LENGTH_SHORT).show();
                    new Handler().postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            finish();
                        }
                    }, 1000);
                }
                break;
        }
    }

    private void initView() {
        btCreate = findViewById(R.id.bt_create);
        btImport = findViewById(R.id.bt_import);
        etMnemonic = findViewById(R.id.et_mnemonic);

        btCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        String[] pathArray = ETH_JAXX_TYPE.split("/");
                        String passphrase = "";
                        long creationTimeSeconds = System.currentTimeMillis() / 1000;
                        DeterministicSeed ds = new DeterministicSeed(secureRandom, 128, passphrase, creationTimeSeconds);
                        createWallet(ds, pathArray);
                    }
                }).start();

            }
        });

        btImport.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (!etMnemonic.getText().toString().trim().equals("")) {
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            importWallet(etMnemonic.getText().toString().trim());
                        }
                    }).start();
                } else {
                    Toast.makeText(MainActivity.this, "pls input mnemonic", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    /**
     * import mnemonic wallet
     * @param mnemonic
     */
    private void importWallet(String mnemonic) {
        String[] pathArray = ETH_JAXX_TYPE.split("/");
        if (pathArray.length <= 1) {
            //内容不对
            return ;
        }
        String passphrase = "";
        long creationTimeSeconds = System.currentTimeMillis() / 1000;
        DeterministicSeed ds = new DeterministicSeed(Arrays.asList(mnemonic.split(" ")), null, passphrase, creationTimeSeconds);
        createWallet(ds, pathArray);
    }

    /**
     * create wallet
     */
    private void createWallet(DeterministicSeed ds, String[] pathArray) {

        byte[] seedBytes = ds.getSeedBytes();
        List<String> mnemonicCode = ds.getMnemonicCode();

        DeterministicKey masterPrivateKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);

        for (int i = 1; i < pathArray.length; i++) {
            ChildNumber childNumber;
            if (pathArray[i].endsWith("'")) {
                int number = Integer.parseInt(pathArray[i].substring(0, pathArray[i].length() - 1));
                childNumber = new ChildNumber(number, true);
            } else {
                int number = Integer.parseInt(pathArray[i]);
                childNumber = new ChildNumber(number, false);
            }

            masterPrivateKey = HDKeyDerivation.deriveChildKey(masterPrivateKey, childNumber);
        }

        ECKeyPair ecKeyPair = ECKeyPair.create(masterPrivateKey.getPrivKeyBytes());
        WalletFile walletFile;
        try {
            walletFile = Wallet.create(password, ecKeyPair, 1024, 1);

            String address = Numeric.prependHexPrefix(Keys.getAddress(ecKeyPair));
            String mnemonic = convertMnemonicList(mnemonicCode);
            Logger.d("Et Mnemonic : " + mnemonic);
            Logger.d("Et Address : " + address);

        } catch (CipherException e) {
            e.printStackTrace();
        }
    }

    /**
     * covert mnemonic string to List<String>
     * @param mnemonics
     * @return
     */
    private static String convertMnemonicList(List<String> mnemonics) {
        StringBuilder sb = new StringBuilder();
        for (String mnemonic : mnemonics
                ) {
            sb.append(mnemonic);
            sb.append(" ");
        }
        return sb.toString();
    }
}
