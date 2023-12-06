package com.poly.dao;

import java.util.List;
import java.util.Map;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.poly.entity.Order;

public interface OrderDAO extends JpaRepository<Order, Long> {
	@Query("SELECT o FROM Order o WHERE o.account.username=?1")
	List<Order> findByUsername(String username);
	
	@Query(value = "EXEC THONGKE :DieuKien",nativeQuery = true)
	List<Map<String, Object>> ThongKe(String DieuKien);
}
