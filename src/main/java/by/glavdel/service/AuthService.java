package by.glavdel.service;

import by.glavdel.dao.UserDao;
import by.glavdel.dtoentity.UserDto;
import by.glavdel.entity.User;
import by.glavdel.exception.AuthenticatException;
import by.glavdel.exception.ExceptionMessageConstant;
import by.glavdel.exception.NotFoundException;
import by.glavdel.mapper.UserRequestMapper;
import by.glavdel.mapper.dto.MapperDto;
import by.glavdel.request.LoginRequest;
import by.glavdel.request.RefreshJwtRequest;
import by.glavdel.request.SignUpRequest;
import by.glavdel.response.AuthResponse;
import by.glavdel.security.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthService {
    private final JwtProvider jwtProvider;
    private final UserRequestMapper userRequestMapper;
    private final AuthenticationManager authenticationManager;

    private final UserDao userDao;
    private final MapperDto<User, UserDto> userDtoMapper;

    private final Map<String, String> refreshStorage = new HashMap<>();

    private final PasswordEncoder passwordEncoder;

    public AuthResponse createUser(SignUpRequest request) {
        UserDto dto = userRequestMapper.signupRequestToDto(request);
        dto.setPassword(passwordEncoder.encode(dto.getPassword()));
        userDao.add(userDtoMapper.dtoToEntity(dto));
        return AuthResponse.builder()
                .accessToken(generateAccessToken(dto))
                .refreshToken(generateRefreshToken(dto))
                .build();
    }

    public AuthResponse authenticateUser(LoginRequest request) {
        UserDto dto = userDtoMapper.entityToDto(userDao.findByUsername(request.getUsername())
                .orElseThrow(() -> new NotFoundException(ExceptionMessageConstant.NOT_FOUND_USER)));
        UsernamePasswordAuthenticationToken authInputToken =
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        Authentication authentication = authenticationManager.authenticate(authInputToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return AuthResponse.builder()
                .accessToken(generateAccessToken(dto))
                .refreshToken(generateRefreshToken(dto))
                .build();
    }

    public AuthResponse getAccessToken(RefreshJwtRequest request) {
        try {
            UserDto dto = getUserDtoFromRefreshToren(request);
            String accessToken = jwtProvider.generateAccessToken(dto);
            return new AuthResponse(accessToken, null);
        } catch (AuthenticatException e) {
            return new AuthResponse(null, null);
        }
    }

    public AuthResponse refresh(RefreshJwtRequest request) {
        UserDto dto = getUserDtoFromRefreshToren(request);
        String accessToken = jwtProvider.generateAccessToken(dto);
        String newRefreshToken = jwtProvider.generateRefreshToken(dto);
        refreshStorage.put(dto.getUsername(), newRefreshToken);
        return new AuthResponse(accessToken, newRefreshToken);
    }

    private UserDto getUserDtoFromRefreshToren(RefreshJwtRequest request) {
        String refreshToken = request.getRefreshToken();
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            String username = jwtProvider.getLoginFromRefreshToken(refreshToken);
            String saveRefreshToken = refreshStorage.get(username);
            if (saveRefreshToken != null && saveRefreshToken.equals(refreshToken)) {
                return userDtoMapper.entityToDto(userDao.findByUsername(username)
                        .orElseThrow(() -> new NotFoundException(ExceptionMessageConstant.NOT_FOUND_USER)));
            }
        }
        throw new AuthenticatException(ExceptionMessageConstant.INVALID_TOKEN);
    }

    private String generateAccessToken(UserDto dto) {
        return jwtProvider.generateAccessToken(dto);
    }

    private String generateRefreshToken(UserDto dto) {
        return jwtProvider.generateRefreshToken(dto);
    }
}
