package com.jwt.security.system.controller;

import com.jwt.security.security.entity.CurrentUser;
import com.jwt.security.system.entity.User;
import com.jwt.security.system.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private CurrentUser currentUser;

    @RequestMapping("/hello")
    public String hello(){
        return "Hello";
    }

    @GetMapping("/user/getAllUser")
    @PreAuthorize("hasAnyRole('ROLE_DEV','ROLE_PM','ROLE_ADMIN')")
    public ResponseEntity<Page<User>> getAllUser(@RequestParam(value = "pageNum", defaultValue = "0") int pageNum,
                                                 @RequestParam(value = "pageSize", defaultValue = "10") int pageSize) {
        System.out.println("当前访问该接口的用户为：" + currentUser.getCurrentUser().toString());
        Page<User> allUser = userService.getAllUser(pageNum, pageSize);
        return ResponseEntity.ok().body(allUser);
    }

    @DeleteMapping("/user/deleteUserByName")
    @PreAuthorize(("hasAnyRole('ROLE_ADMIN')"))
    public ResponseEntity<User> deleteUserByName(@RequestParam("username") String username) {
        userService.deleteUserByUserName(username);
        return ResponseEntity.ok().build();
    }
}
