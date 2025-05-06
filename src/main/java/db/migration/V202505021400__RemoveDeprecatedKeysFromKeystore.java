package db.migration;

import com.czertainly.cp.soft.util.KeyStoreUtil;
import com.czertainly.cp.soft.util.SecretEncodingVersion;
import com.czertainly.cp.soft.util.SecretsUtil;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPrivateKey;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.security.Key;
import java.security.KeyStore;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Types;
import java.util.Base64;
import java.util.Collections;

@SuppressWarnings("java:S101")
public class V202505021400__RemoveDeprecatedKeysFromKeystore extends BaseJavaMigration {

    @Override
    public void migrate(Context context) throws Exception {
        try (final Statement select = context.getConnection().createStatement()) {
            ResultSet tokens = select.executeQuery("SELECT uuid, code, data FROM token_instance;");
            String updateTokenData = "UPDATE token_instance SET data = ? WHERE uuid = ?;";
            try (PreparedStatement preparedStatement = context.getConnection().prepareStatement(updateTokenData)) {
                while (tokens.next()) {
                    String password = SecretsUtil.decodeAndDecryptSecretString(tokens.getString("code"), SecretEncodingVersion.V1);
                    KeyStore keyStore = KeyStoreUtil.loadKeystore(Base64.getDecoder().decode(tokens.getString("data")), password);
                    for (String alias : Collections.list(keyStore.aliases())) {
                        if (keyStore.isKeyEntry(alias)) {
                            Key privateKeyEntry = keyStore.getKey(alias, password.toCharArray());
                            if (hasDeprecatedAlgorithm(privateKeyEntry)) keyStore.deleteEntry(alias);
                        }
                    }
                    preparedStatement.setString(1, Base64.getEncoder().encodeToString(KeyStoreUtil.saveKeystore(keyStore, password)));
                    preparedStatement.setObject(2, tokens.getObject("uuid"), Types.OTHER);
                    preparedStatement.addBatch();
                }
                preparedStatement.executeBatch();
            }
        }
    }

    private boolean hasDeprecatedAlgorithm(Key privateKey) {
        return (privateKey instanceof BCDilithiumPrivateKey || privateKey instanceof BCSPHINCSPlusPrivateKey);
    }

}
