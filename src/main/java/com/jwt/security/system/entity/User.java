package com.jwt.security.system.entity;

import com.jwt.security.system.enums.UserStatus;
import lombok.Data;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import javax.persistence.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Data
@Table(name = "user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "status")
    private UserStatus status;

    @Column(name = "role")
    private String role;

    public List<SimpleGrantedAuthority> getRoles(){
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        Arrays.stream(role.split(",")).forEach(role -> authorityList.add(new SimpleGrantedAuthority("ROLE_" + role)));
        return authorityList;
    }

}
