package com.mohyehia.authserver.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.mohyehia.authserver.entities.User;
import com.mohyehia.authserver.repositories.UserRepository;

@Service
public class UserService implements UserDetailsService{
	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("Username not found!"));
		
		new AccountStatusUserDetailsChecker().check(user);
		return user;
	}
	
}
