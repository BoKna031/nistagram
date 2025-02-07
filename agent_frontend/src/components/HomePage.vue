<template>
    <div>
        <template>
          <div class="text-center" v-if="showCart" @close="showCart=false">
            <v-dialog
              v-model="showCart"
              width="600px"
            >
              <v-card class="mx-auto my-12" width="600px" >
                  <v-card-title class="justify-center">Your shopping cart</v-card-title>
                 
                  <v-simple-table fixed-header height="300px">
                    <template v-slot:default>
                      <thead>
                        <tr>
                          <th class="text-center">
                            Product
                          </th>
                          <th class="text-center">
                            Amount
                          </th>
                          <th class="text-center">
                            Price (RSD)
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr
                          v-for="item in cart"
                          :key="item.id"
                        >
                          <td>{{ item.name }}</td>
                          <td>{{ item.amount }}</td>
                          <td>{{ item.pricePerItem }}</td>
                        </tr>
                      </tbody>
                    </template>
                  </v-simple-table>

                  <v-card-title >Full price: {{fullPrice}} RSD</v-card-title>
                    <v-spacer></v-spacer>
                    <v-btn
                      color="green darken-1"
                      text
                      @click="makeOrder()"
                    >
                      Make order
                    </v-btn>
              </v-card>
            </v-dialog>
          </div>
          <v-container class="fill-height">
            <v-row>
              <v-col v-for="p in products" :key="p.id" cols="12" sm="4">
                <v-card class="mx-auto my-12" width="330" >
                    <template v-if="hasRole('AGENT')">
                    <v-menu offset-y>
                      <template v-slot:activator="{ on, attrs }">
                        <v-btn icon v-bind="attrs" v-on="on">
                          <v-icon>mdi-dots-vertical</v-icon>
                        </v-btn>
                      </template>
                      <v-list>
                        <v-list-item>
                          <v-list-item-title @click="sendItem(p)"><router-link :to="{ name: 'EditProduct'}">Edit</router-link></v-list-item-title>
                        </v-list-item>
                        <v-list-item>
                          <v-list-item-title @click="deleteProduct(p.id)"><router-link  :to="{ name: 'HomePage'}">Delete</router-link></v-list-item-title>
                        </v-list-item>
                      </v-list>
                  </v-menu>
                  </template>   
                  <template slot="progress">
                    <v-progress-linear color="deep-purple" height="10" indeterminate ></v-progress-linear>
                  </template>
                    <v-img contain width="330" height="440" :src="protocol + '://' + server + '/data/' + p.picturePath"></v-img>
                  <v-card-title>{{p.name}}</v-card-title>

                  <v-card-text>
                    <div class="my-4 text-subtitle-1">
                      {{p.pricePerItem}} RSD
                    </div>

                    <div>{{p.description}}</div>
                  </v-card-text>

                  <v-divider class="mx-4"></v-divider>

                  <v-card-title>Choose amount:</v-card-title>

                  <v-card-text>
                    <v-chip-group column >
                      <v-chip>
                        <input v-model="productAmount[p.id]" type="number" min="1" value="1" style="width: 50px">
                      </v-chip>
                      <v-chip>
                        <v-card-actions>
                          <v-btn color="deep-purple lighten-2" text @click="addToCart(p)" >
                            Add to cart
                          </v-btn>
                        </v-card-actions>
                      </v-chip>
                    </v-chip-group>
                  </v-card-text>
                </v-card>
              </v-col>
            </v-row>
          </v-container>
        </template>
    </div>
</template>

<script>
import axios from 'axios'
import * as comm from '../configuration/communication.js'
import { bus } from '../main'
  export default {
    name: "HomePage",
    data() {return {
      protocol : comm.protocol,
      server : comm.static_server,
      products: [],
      productAmount:{},
      cart:[],
      showCart : false,
      fullPrice: 0
    }},
    created(){
      bus.$on('show-cart', (data) => {
      this.showCart = data;
      this.fullPrice = 0;
      for (let item of this.cart){
        this.fullPrice += item.amount * item.pricePerItem;
      }
    })
    },
    mounted(){
       this.getProducts();
    },
    methods: {
    sendItem(item){
       bus.$emit('product-data', item);
    },
     hasRole(role){
      return comm.hasRole(role);
    },
     deleteProduct(id){
       axios({
                method: "delete",
                url: comm.protocol +'://' + comm.server + '/product/' + id,
                headers: comm.getHeader()
            }).then(response => {
              if(response.status==200){
                console.log("ok");
              }
            }).catch(() => {
              console.log("error")
            });
      this.getProducts();
    },
     getProducts(){
       axios({
                method: "get",
                url: comm.protocol +'://' + comm.server + '/product',
            }).then(response => {
              if(response.status==200){
                this.products = response.data;
                console.log(this.products);
              }
            }).catch((response) => {
              console.log(response.data)
            });
     }, 
     addToCart(p){
       p.amount = 1;
       if(this.productAmount[p.id] != null)
          p.amount = this.productAmount[p.id];
       for (let item of this.cart){
         if (p.id == item.id){
           return;
         }
       }
       this.cart.push(p);
     },
     makeOrder(){
       if(!comm.isUserLogged()){
         alert("You need to be logged in to make order!");
         return;
       }
       let data = {};
       let items = [];
       for (let p of this.cart){
         let item = {"productId" : p.id, "quantity" : parseInt(p.amount)};
         items.push(item);
       }
       data.items = items;
       let json = JSON.stringify(data)
       axios({
                method: "post",
                url: comm.protocol +'://' + comm.server + '/order',
                data: json,
                headers: comm.getHeader()
            }).then(response => {
              if(response.status==200){
                console.log("ok");
              }
            }).catch(() => {
              console.log("error")
            })
       this.showCart = false;
     }
    },
  }
</script>