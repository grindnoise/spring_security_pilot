package com.example.repository;

import com.example.entity.Account;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountsRepository extends CrudRepository<Account, Long> {

    Account findByCustomerId(long customerId);

}
