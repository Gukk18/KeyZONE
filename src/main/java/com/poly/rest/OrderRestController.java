package com.poly.rest;

import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.poly.dao.OrderDAO;
import com.poly.dao.OrderDetailDAO;
import com.poly.entity.Order;
import com.poly.entity.OrderDetail;
import com.poly.service.OrderService;

@CrossOrigin("*")
@RestController
@RequestMapping("/rest/orders")
public class OrderRestController {

	@Autowired
	OrderService orderService;

	@Autowired
	OrderDAO orderDAO;

	@Autowired
	OrderDetailDAO orderDetailDAO;

	@Autowired
	HttpSession session;

	@PostMapping
	public Order create(@RequestBody JsonNode orderData) {
		System.out.println(orderData);
		return orderService.create(orderData);
	}

	@PostMapping("/cancel")
	public ResponseEntity<?> cancel(
			@RequestParam("idOrder") Optional<String> idOrder,
			@RequestParam("user") Optional<String> username) {
		Order order = orderService.findById(Long.parseLong(idOrder.orElse(null)));
		if (!order.getAccount().getUsername().equals(username.orElse(null))) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"errorCode\": \"You do not have the right to cancel the order\"}");
		}
		if (!order.getStatus().equals("CHOXULY")) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"errorCode\":Orders pending processing will be canceled\"\"}");
		}
		orderDAO.delete(order);
		return ResponseEntity.ok(true);
	}

	@GetMapping("/getall")
	public List<Order> getall() {
		return orderDAO.findAll();
	}

	@GetMapping("/getalldetail")
	public List<OrderDetail> getallDetail(
			@RequestParam("idOrder") Long iDOrder) {
		return orderDetailDAO.findByOrder(orderDAO.findById(iDOrder).get());
	}

	@PostMapping("/update")
	public void update(
			@RequestBody JsonNode orderJson )  {
		ObjectMapper mapper = new ObjectMapper();
		Order order = mapper.convertValue(orderJson, Order.class);
		
		
		
		Order orderold = orderDAO.findById(order.getId()).orElse(null);
		orderold.setAddress(order.getAddress());
		orderold.setStatus(order.getStatus());
		orderDAO.save(orderold);
	}
}

