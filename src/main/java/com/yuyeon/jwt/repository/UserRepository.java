package com.yuyeon.jwt.repository;

import com.yuyeon.jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

    // findBy규칙 -> Username 문법
    // select * from user where username = 1?
    public User findByUsername(String username); //JPA Query Methods
}
