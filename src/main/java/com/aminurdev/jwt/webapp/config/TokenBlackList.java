package com.aminurdev.jwt.webapp.config;

import java.util.HashSet;
import java.util.Set;

public class TokenBlackList {

    private static final Set<String> blackList = new HashSet<>();

    public static void addToBlacklist(String token) {

        blackList.add(token);
    }

    public static boolean isBlacklisted(String token) {

        return blackList.contains(token);
    }

    public static void removeFromBlacklist(String token) {
        blackList.remove(token);
    }
}
