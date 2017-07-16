function getByTag(x){
  return document.getElementsByTagName(x);
}
function getById(x){
  return document.getElementById(x);
}
function getByClass(x){
	return document.getElementsByClassName(x);
}
function showMenu(evt){
	getByClass("slide_menu")[0].style.width = "21%";
}
function ChangeWidthSlowly(elem,AtTime,totalTime,finalSize,initialSize){
	// console.log("yhuy");
	var slope = (finalSize-initialSize)/totalTime;
	var widthAtTimet = slope*(AtTime) + initialSize; 
	elem.style.width = widthAtTimet +"px";
}
var addEvent = function(elem, type, eventHandle){
  if (elem == null || typeof(elem) == 'undefined') return;
  if ( elem.addEventListener ) {
    elem.addEventListener( type, eventHandle, false );
  } 
  else if ( elem.attachEvent ) {
    elem.attachEvent( "on" + type, eventHandle );
  } 
  else {
    elem["on"+type]=eventHandle;
  }
}
function ExpandMenuHeight(){
	//alert(window.innerHeight);
	var slideMenu= document.getElementsByClassName("slide_menu")[0];
	var feedContainer= document.getElementsByClassName("center_container")[0];
    slideMenu.style.height = window.innerHeight+"px";
    feedContainer.style.height = window.innerHeight+"px";
        // slideMenu.style.display= 'block';
}
window.onload = ExpandMenuHeight;
//////////////////////////////////////////////////////////////////////
function yourHandler(e){
	e= e || window.event;
	var target = e.target || e.srcElement;
}

// var math_stuff_app = angular.module("maths_stuff", []);
// ################################################################### //

var math_stuff_app = angular.module("maths_stuff", ['ngRoute']);

math_stuff_app.config(function($routeProvider) {
    $routeProvider
    .when("/all_maths", {
        templateUrl : "all_maths.html",
        controller: 'AllMathsController'
    })
    .when("/all_algos", {
        templateUrl : "all_algos.html",
        controller: 'AllAlgosController'
    })
    .when("/all_probs", {
        templateUrl : "all_probs.html",
        controller: 'AllProbsController'
    })
    .when("/all_deep_learning", {
        templateUrl : "all_deep_learning.html",
        controller: 'AllDeepLearningController'
    })
    .when("/all_ML", {
        templateUrl : "all_ML.html",
        controller: 'AllMLController'
    })
    .otherwise({
        redirectTo: '/all_probs'
      });
});

math_stuff_app.controller('AllMathsController', function($scope) {
	
	$scope.message = 'This is maths controller';
	
});

math_stuff_app.controller('AllAlgosController', function($scope) {
	
	$scope.message = 'This is algos controller';
	
});
math_stuff_app.controller('AllProbsController', function($scope) {
	
	$scope.message = 'This is probability controller';
	
});
math_stuff_app.controller('AllDeepLearningController', function($scope) {
	
	$scope.message = 'This is deep learning controller';
	
});
math_stuff_app.controller('AllMLController', function($scope) {
	
	$scope.message = 'This is ML controller';
	
});

math_stuff_app.controller('feed_generator', function($scope) {
  
  $scope.message = 'This is feed generator controller';
  
});

