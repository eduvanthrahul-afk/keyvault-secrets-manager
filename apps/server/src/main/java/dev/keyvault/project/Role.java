package dev.keyvault.project;

/**
 * Project roles, ordered by privilege. Roles govern what the SERVER allows (mutations, admin);
 * environment key grants govern what a member can actually DECRYPT. Both must agree.
 */
public enum Role {
    VIEWER,     // read secrets in granted environments
    DEVELOPER,  // + create/update/delete secrets, create service tokens
    ADMIN,      // + manage members, environments, grants, key rotation
    OWNER;      // + delete project, manage owners

    public boolean atLeast(Role other) {
        return compareTo(other) >= 0;
    }
}
