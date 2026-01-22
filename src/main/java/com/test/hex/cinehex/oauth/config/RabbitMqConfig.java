package com.test.hex.cinehex.oauth.config;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMqConfig {

    public static final String EXCHANGE_NAME = "cinehex.users.exchange";
    public static final String ROUTING_KEY = "users.registered";

    // 1. Convertidor JSON: Vital para que no envíe bytes ilegibles de Java
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    // 2. Declarar el Exchange (El "Buzón" de salida)
    // Usamos TopicExchange para permitir ruteo flexible en el futuro
    @Bean
    public TopicExchange usersExchange() {
        return new TopicExchange(EXCHANGE_NAME);
    }

    // Configura el Template para usar el convertidor JSON
    // Usamos un nombre diferente para evitar conflictos con la autoconfiguración
    @Bean
    public AmqpTemplate customRabbitTemplate(ConnectionFactory connectionFactory) {
        final RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(jsonMessageConverter());
        return rabbitTemplate;
    }
}
