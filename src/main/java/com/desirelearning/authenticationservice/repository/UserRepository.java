package com.desirelearning.authenticationservice.repository;


import com.desirelearning.authenticationservice.entity.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends CrudRepository<User,Integer> {
     List<User> findByEmail(String email);
}
