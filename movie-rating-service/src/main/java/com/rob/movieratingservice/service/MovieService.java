package com.rob.movieratingservice.service;

import com.rob.movieratingservice.model.Movie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class MovieService {

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Value("${service.movie-service}")
    private static String serviceName;
    private static String baseUrl="http://MOVIE-SERVICE/movies";

    public Movie getMovie(int movieId){
        Movie movie = webClientBuilder.build()
                .get()
                .uri(baseUrl+"/"+movieId)
                .retrieve()
                .bodyToMono(Movie.class)
                .block();
        return movie;
    }
}
