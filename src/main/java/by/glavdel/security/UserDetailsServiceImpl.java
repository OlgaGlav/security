package by.glavdel.security;

import by.glavdel.dao.UserDao;
import by.glavdel.entity.User;
import by.glavdel.exception.ExceptionMessageConstant;
import by.glavdel.exception.NotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserDao userDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userDao.findByUsername(username)
                .orElseThrow(() -> new NotFoundException(ExceptionMessageConstant.NOT_FOUND_USER));
        return UserDetailsImpl.fromUserToUserDetails(user);
    }
}
