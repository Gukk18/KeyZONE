app = angular.module("admin-app",["ngRoute"]);
app.config(function($routeProvider){
    $routeProvider
    .when("/account",{
        templateUrl:"/assets/admin/account/index.html",
        controller:"account-ctrl"
    })
    
    .when("/product",{
        templateUrl:"/assets/admin/product/index.html",
        controller:"product-ctrl"
    })
    .when("/statistical",{
        templateUrl:"/assets/admin/product/statistical.html",
        controller:"statistical-ctrl"
    })
    .when("/category",{
        templateUrl:"/assets/admin/category/index.html",
        controller:"category-ctrl"
    })
    
    .when("/authorize",{
        templateUrl:"/assets/admin/authority/index.html",
        controller:"authority-ctrl"
    })

    .when("/unauthorized",{
        templateUrl:"/assets/admin/authority/unauthorized.html",
        controller:"authority-ctrl"
    })
    .otherwise({
        template:"<h1 class='text-center'>Admin panel </h1>"
    });
});