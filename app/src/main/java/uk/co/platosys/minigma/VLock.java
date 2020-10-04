package uk.co.platosys.minigma;


import uk.co.platosys.minigma.exceptions.MinigmaException;

/**
 * This extension of Lock provides a couple of additional fields
 * for use with Hagrid verifying keyservers.
 */


public class VLock extends Lock {
    private String token;
    private String email;
    public VLock(Lock lock) throws MinigmaException {
        super(lock.getBytes());
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
