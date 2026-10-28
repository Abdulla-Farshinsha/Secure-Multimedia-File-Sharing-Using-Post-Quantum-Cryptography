package edu.course.pqfileshare;

import java.nio.file.Path;
import java.security.KeyPair;

/** An unlocked local account for the lifetime of the desktop-app session. */
public record AccountSession(long id, String username, Path keyStorePath, KeyPair keys) { }
