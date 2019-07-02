package com.yc.shiro.mapper;

import com.yc.shiro.beans.User;

import java.util.List;

public interface UserMapper {
    List<User> selectAll();

    int createUser(User user);

    User selectByUsername(String username);
}
