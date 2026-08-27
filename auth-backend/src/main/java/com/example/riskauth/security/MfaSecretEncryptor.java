package com.example.riskauth.security;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Converter
public class MfaSecretEncryptor implements AttributeConverter<String, String> {

    private static final String ENCRYPTION_KEY = System.getenv("MFA_ENCRYPTION_KEY");
    private static final String ALGORITHM = "AES";

    private void validateKey() {
        if (ENCRYPTION_KEY == null || (ENCRYPTION_KEY.length() != 16 && ENCRYPTION_KEY.length() != 32)) {
            throw new IllegalStateException("KRITIČNA BEZBEDNOSNA GREŠKA: MFA_ENCRYPTION_KEY nije setovan u sistemskim varijablama ili nije ispravne dužine (mora biti 16 ili 32 karaktera)!");
        }
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null || attribute.isEmpty()) {
            return null;
        }
        validateKey();
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encryptedBytes = cipher.doFinal(attribute.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Greška pri kriptovanju MFA tajne", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isEmpty()) {
            return null;
        }
        validateKey();
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(dbData));
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Greška pri dešifrovanju MFA tajne. Moguće da je u bazi ostao nekriptovan podatak.", e);
        }
    }
}