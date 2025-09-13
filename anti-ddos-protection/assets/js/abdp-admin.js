(function() {
    const apiBase = abdpData.apiBase;
    let nonce = abdpData.nonce;

    let blockedChart, bannedChart, highTrafficChart;

    function fetchNonce() {
        return fetch(abdpData.ajaxUrl + '?action=abdp_refresh_nonce', {
            headers: { 'X-WP-Nonce': nonce }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to refresh nonce: ' + response.statusText);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                nonce = data.data;
                return nonce;
            } else {
                throw new Error('Nonce refresh failed');
            }
        });
    }

    function processData(data) {
        let counts = {};
        data.forEach(entry => {
            let date = entry.timestamp.split(' ')[0];
            counts[date] = (counts[date] || 0) + 1;
        });
        let sortedDates = Object.keys(counts).sort();
        let labels = sortedDates;
        let values = sortedDates.map(d => counts[d]);
        return { labels, values };
    }

    function drawChart(ctx, labels, values, title, existingChart) {
        if (existingChart) {
            existingChart.destroy();
        }
        return new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: title,
                    data: values,
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Count'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Date'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true
                    }
                }
            }
        });
    }

    function fetchLogs(endpoint, tableId, chartId, title) {
        fetch(apiBase + endpoint, {
            headers: { 'X-WP-Nonce': nonce }
        })
        .then(response => {
            if (response.status === 403) {
                return fetchNonce().then(() => {
                    return fetch(apiBase + endpoint, {
                        headers: { 'X-WP-Nonce': nonce }
                    });
                });
            }
            return response;
        })
        .then(response => response.json())
        .then(data => {
            const tbody = document.querySelector(`#${tableId} tbody`);
            if (!tbody) return;
            tbody.innerHTML = ''; // Clear existing rows
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="' + (endpoint === '/banned-ips' ? 4 : 3) + '">No entries recorded yet.</td></tr>';
            } else {
                data.forEach(entry => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${entry.ip}</td>
                        <td>${entry.user_agent}</td>
                        <td>${entry.timestamp}</td>
                        ${endpoint === '/banned-ips' ? `<td>${entry.expires}</td>` : ''}
                    `;
                    tbody.appendChild(row);
                });
            }

            // Draw chart
            const ctx = document.getElementById(chartId).getContext('2d');
            const { labels, values } = processData(data);
            if (chartId === 'blocked-ips-chart') {
                blockedChart = drawChart(ctx, labels, values, title, blockedChart);
            } else if (chartId === 'banned-ips-chart') {
                bannedChart = drawChart(ctx, labels, values, title, bannedChart);
            } else if (chartId === 'high-traffic-bots-chart') {
                highTrafficChart = drawChart(ctx, labels, values, title, highTrafficChart);
            }
        })
        .catch(error => {
            console.error('Error fetching logs:', error);
        });
    }

    function refreshLogs() {
        fetchLogs('/blocked-ips', 'abdp-blocked-ips-table', 'blocked-ips-chart', 'Blocked IPs per Day');
        fetchLogs('/banned-ips', 'abdp-banned-ips-table', 'banned-ips-chart', 'Banned IPs per Day');
        fetchLogs('/high-traffic-bots', 'abdp-high-traffic-bots-table', 'high-traffic-bots-chart', 'High Traffic Bots per Day');
    }

    // Initial fetch
    refreshLogs();

    // Refresh every 30 seconds
    setInterval(refreshLogs, 30000);
})();
