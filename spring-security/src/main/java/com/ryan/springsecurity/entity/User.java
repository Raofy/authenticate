package com.ryan.springsecurity.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;


@Setter
@Getter
@AllArgsConstructor
public class User implements UserDetails {

    private long id;

    private String name;

    private String password;

    private Boolean enabled;

    private List<GrantedAuthority> authorities;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.name;
    }

    /**
     * 指示用户的帐户是否已过期。 过期的帐户无法通过身份验证。
     *
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 指示用户是锁定还是解锁。 锁定的用户无法通过身份验证。
     *
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 指示用户的凭据（密码）是否已过期。 过期凭据会阻止身份验证。
     *
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 指示启用还是禁用用户。 禁用的用户无法通过身份验证。
     *
     * @return
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }
}
