import axios from 'axios';

async function displayPlans() {
  try {
    const response = await axios.get('http://localhost:3000/data/plans');
    const plans = response.data;

    console.log('=== Available Plans ===\n');

    plans.forEach(plan => {
      console.log(`ID: ${plan.id}`);
      console.log(`Name: ${plan.name}`);
      console.log(`Network: ${plan.network}`);
      console.log(`Size: ${plan.size}`);
      console.log(`Price: ₦${plan.price}`);
      console.log(`Created At: ${new Date(plan.created_at).toLocaleString()}`);
      console.log('---------------------------');
    });

  } catch (err) {
    console.error('Error fetching plans:', err.response ? err.response.data : err.message);
  }
}

displayPlans();
