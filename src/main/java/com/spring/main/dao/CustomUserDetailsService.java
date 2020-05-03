package com.spring.main.dao;

import com.spring.main.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired JdbcTemplate template;
    
    @Value("${getUserQuery}")
    private String getUserQuery;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        User user = new User();
        user.setAuthorities(authorities);
        template.query(getUserQuery, (resultSet, i) -> {
                user.setUsername(resultSet.getString(1));
                user.setPassword(resultSet.getString(2));
                user.setActive(resultSet.getBoolean(3));
                authorities.add(new SimpleGrantedAuthority(resultSet.getString(4)));
                return user;
        });
        if(user.getAuthorities().isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }
        return user;
    }

    @Bean
    PasswordEncoder getEncoder(){
        return new BCryptPasswordEncoder(10);
    }

}
