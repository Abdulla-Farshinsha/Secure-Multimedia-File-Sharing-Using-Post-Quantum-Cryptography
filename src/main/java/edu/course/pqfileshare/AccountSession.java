package edu.course.pqfileshare;

import java.nio.file.Path;
import java.security.KeyPair;

/** Unlocked local account keys held for the lifetime of the desktop-app session. */
public record AccountSession(long id, String username, Path keyStorePath, KeyPair keys, KeyPair signingKeys) { }
