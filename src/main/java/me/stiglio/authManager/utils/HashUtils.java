package me.stiglio.authManager.utils;

import org.mindrot.jbcrypt.BCrypt;

public class HashUtils {

    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean checkPassword(String password, String hash) {
        return BCrypt.checkpw(password, hash);
    }
}
