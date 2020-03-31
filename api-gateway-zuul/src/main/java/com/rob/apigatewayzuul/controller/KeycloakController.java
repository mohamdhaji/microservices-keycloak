package com.rob.apigatewayzuul.controller;

import com.rob.apigatewayzuul.model.UserCredentials;
import com.rob.apigatewayzuul.model.UserDTO;
import com.rob.apigatewayzuul.service.KeyCloakService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/keycloak")
public class KeycloakController {

	@Autowired
	KeyCloakService keyClockService;

	/*
	 * Get token for the first time when user log in. We need to pass
	 * credentials only once. Later communication will be done by sending token.
	 */

	@RequestMapping(value = "/token", method = RequestMethod.POST)
	public ResponseEntity<?> getTokenUsingCredentials(@RequestBody UserCredentials userCredentials) {

		String responseToken = null;
		try {

			responseToken = keyClockService.getToken(userCredentials);

		} catch (Exception e) {

			return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
		}

		return new ResponseEntity<>(responseToken, HttpStatus.OK);

	}

	/*
	 * When access token get expired than send refresh token to get new access
	 * token. We will receive new refresh token also in this response.Update
	 * client cookie with updated refresh and access token
	 */
	@RequestMapping(value = "/refreshtoken", method = RequestMethod.GET)
	public ResponseEntity<?> getTokenUsingRefreshToken(@RequestHeader(value = "Authorization") String refreshToken) {

		String responseToken = null;
		try {

			responseToken = keyClockService.getByRefreshToken(refreshToken);

		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
		}

		return new ResponseEntity<>(responseToken, HttpStatus.OK);

	}

	/*
	 * Creating user in keycloak passing UserDTO contains username, emailid,
	 * password, firtname, lastname
	 */
	@RequestMapping(value = "/create", method = RequestMethod.POST)
	public ResponseEntity<?> createUser(@RequestBody UserDTO userDTO) {
		try {

			return keyClockService.createUserInKeyCloak(userDTO);
		}

		catch (Exception ex) {

			ex.printStackTrace();
			return new ResponseEntity<>("Username==" + userDTO.getUserName() + " could not be created in keycloak", HttpStatus.BAD_REQUEST);

		}

	}
}
