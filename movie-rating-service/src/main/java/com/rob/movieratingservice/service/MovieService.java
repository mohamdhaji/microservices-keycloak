package com.rob.movieratingservice.service;

import com.rob.movieratingservice.model.Movie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class MovieService {

    @Autowired
    private WebClient.Builder webClientBuilder;

//    @Value("${service.movie-service}")
//    private static String serviceName;

//    private static String baseUrl="http://127.0.0.1:9100/movies";

    RestTemplate restTemplate = new RestTemplate();

  public Movie getMovie(int movieId){
//        Movie movie = webClientBuilder.build()
//                .get()
//                .uri(baseUrl)
//                .retrieve()
//                .bodyToMono(Movie.class)
//                .block();
      Movie movie = restTemplate.getForObject("http://127.0.0.1:8765/movie-service/movies/"+movieId,Movie.class);
        return movie;
    }
}
