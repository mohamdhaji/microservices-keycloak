package com.rob.ratingservice.controller;

import com.rob.ratingservice.model.Rating;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/rating")
public class RatingController {

    @GetMapping
    public List<Rating> all(){
        return Arrays.asList(new Rating(1, 2), new Rating(2, 5));
    }

    @GetMapping("{movieId}")
    public Rating getRating(@PathVariable(name = "movieId", required = true) int movieId){
        return new Rating(movieId, 1);
    }
}
