package com.jwt.security.system.service;

import com.jwt.security.system.entity.User;
import com.jwt.security.system.enums.UserStatus;
import com.jwt.security.system.exception.UserNameAlreadyExistException;
import com.jwt.security.system.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public void saveUser(Map<String, String> registerUser) {
        Optional<User> userOptional = userRepository.findUserByName(registerUser.get("username"));
        if (userOptional.isPresent()) {
            throw new UserNameAlreadyExistException("username already exist");
        }
        User user = new User();
        user.setUsername(registerUser.get("username"));
        user.setPassword(bCryptPasswordEncoder.encode(registerUser.get("password")));
        user.setRole("DEV,PM");
        user.setStatus(UserStatus.CAN_USE);
        userRepository.save(user);
    }

    public User findUserByUserName(String name) {
        return userRepository.findUserByName(name)
                .orElseThrow(() -> new UsernameNotFoundException("No user found with name : " + name));
    }

    public void deleteUserByUserName(String name) {
        userRepository.deleteByUserName(name);
    }

    public Page<User> getAllUser(int pageIndex, int pageSize) {
        return userRepository.findAll(PageRequest.of(pageIndex, pageSize));
    }

}
