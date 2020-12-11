package com.ryan.springsecurity.service.impl;

import com.ryan.springsecurity.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        /**
         * 分发用户权限
         */
        List<GrantedAuthority> authorities = Arrays.asList(
                new SimpleGrantedAuthority("add"),
                new SimpleGrantedAuthority("view"),
                new SimpleGrantedAuthority("update")
//                new SimpleGrantedAuthority("delete")
        );
        User user = new User(1L, username, passwordEncoder.encode("123456"), true, authorities);
        if (null != user) {
            return user;
        }
        return null;
    }
}
