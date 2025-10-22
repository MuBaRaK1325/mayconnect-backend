import axios from 'axios';

async function fetchPlans() {
  try {
    const response = await axios.get('http://localhost:3000/data/plans');
    console.log('Plans fetched successfully:');
    console.log(response.data);
  } catch (err) {
    console.error('Error fetching plans:', err.response ? err.response.data : err.message);
  }
}

fetchPlans();
