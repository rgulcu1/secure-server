package model;

import cryptography.key.PublicKey;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import util.Constants;

import static util.Constants.Status.ONLINE;

@Data
@RequiredArgsConstructor
public class User {

    private final String username;

    private final String password;

    private final String certificate;

    private Constants.Status status = ONLINE;

}
