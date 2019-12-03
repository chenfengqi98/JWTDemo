package com.jwt.security.security.constant;

public class SecurityConstant {

    public static final String AUTH_LOGIN_URL = "/auth/login";

    public static final String ROLE_CLAIMS = "rol";

    public static final long EXPIRATION = 60 * 60L;

    public static final long EXPIRATION_REMEMBER = 60 * 60 * 24 * 7L;

    public static final String JWT_SECRET_KEY = "C*F-JaNdRgUkXn2r5u8x/A?D(G+KbPeShVmYq3s6v9y$B&E)H@McQfTjWnZr4u7w";

    public static final String TOKEN_HEADER = "Authorization";

    public static final String TOKEN_PRIFIX = "Bearer ";

    public static final String TOKEN_TYPE = "JWT";

    public SecurityConstant() {
    }
}
