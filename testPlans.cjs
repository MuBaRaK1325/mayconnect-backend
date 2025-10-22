const axios = require('axios');

async function fetchPlans() {
  try {
    const response = await axios.get('http://localhost:3000/data/plans');
    console.log('Plans data:', response.data);
  } catch (error) {
    console.error('Error fetching plans:', error.response ? error.response.data : error.message);
  }
}

fetchPlans();
