package com.ediscovery.login;

import org.springframework.data.repository.CrudRepository;

public interface UserRepo extends CrudRepository<AppUser,Long> {

     AppUser findByUsername(String userName);

}
