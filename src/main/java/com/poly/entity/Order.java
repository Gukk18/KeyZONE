package com.poly.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;

@SuppressWarnings("serial")
@Data
@Entity
@Table(name = "Orders")
public class Order implements Serializable {


	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	Long id;
	String address;
	@Temporal(TemporalType.TIMESTAMP)
	@Column(name = "Createdate")
	Date createDate = new Date();

	@ManyToOne
	@JoinColumn(name = "Username")
	Account account;

	@JsonIgnore
	@OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
	List<OrderDetail> orderDetails;

	@Column(name = "status", nullable = true)
	String status;

	public void addOrderDetail(OrderDetail orderDetail) {
		orderDetails.add(orderDetail);
		orderDetail.setOrder(this);
	}

	public void removeOrderDetail(OrderDetail orderDetail) {
		orderDetails.remove(orderDetail);
		orderDetail.setOrder(null);
	}
}