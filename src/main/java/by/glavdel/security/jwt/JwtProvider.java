package by.glavdel.security.jwt;

import by.glavdel.dtoentity.UserDto;

public interface JwtProvider {

    String generateAccessToken(UserDto dto);

    String generateRefreshToken(UserDto dto);

    boolean validateAccessToken(String token);

    boolean validateRefreshToken(String token);

    String getLoginFromAccessToken(String token);

    String getLoginFromRefreshToken(String token);
}
