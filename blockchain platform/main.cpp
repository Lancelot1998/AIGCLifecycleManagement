#define _CRT_SECURE_NO_WARNINGS
#include<cstdio>
#include<string>
#include<cstring>
#include<map>
#include<iostream>
#include <fstream>
#define maxn 1024
using namespace std;

map<string, int>num;//�ڵ����ֶ�Ӧ�Ľڵ���
string name[maxn];//�ڵ��Ŷ�Ӧ�Ľڵ�����
int id = 2;
string st;
int ans, head[maxn], net[maxn], ver[maxn];//��ʾ���Ľṹ
int v[maxn], d[maxn], T, n;//d����ӵ�ǰ�ڵ㿪ʼ��������Զ�ľ���
int link1, link2, linkx;
int son[maxn];//��ǰ�ڵ��dֵ�Ǵ��ĸ����ӽڵ���¹�����
int stack[maxn], top;//�洢��
int root;

///////////////////////////
int ioIndex = 0;
extern "C" {
	void test(int a,char *inp,char * outp);
}
////////////////////////////
void initialize() {

	memset(v, 0, sizeof(v));
	memset(head, 0, sizeof(v));
	memset(net, 0, sizeof(v));
	memset(ver, 0, sizeof(v));
	memset(v, 0, sizeof(v));
	memset(d, 0, sizeof(v));
	memset(son, 0, sizeof(v));
	memset(stack, 0, sizeof(v));

}


void dp(int x) {
	v[x] = 1;
	for (int i = head[x]; i; i = net[i]) {
		int y = ver[i];
		if (v[y]) continue;
		dp(y);
		if (d[x] + d[y] + 1 > ans) {//���赱ǰ�ڵ���������Ϸֲ���Ǹ��㣬����ans
			ans = d[x] + d[y] + 1;
			linkx = x;
			link1 = y;
			link2 = son[x];
		}
		if (d[y] + 1 > d[x]) {//�����ǰ�ڵ����´�y�߸�����ô����y��son[x]
			d[x] = d[y] + 1;
			son[x] = y;
		}
	}
}

void add(int x, int y) {
	ver[T] = y;
	net[T] = head[x];
	head[x] = T++;
}

void print1(int x) {
	if (son[x])print1(son[x]);
	stack[top++] = x;
}

void print2(int x) {
	stack[top++] = x;
	if (son[x])print2(son[x]);
}

void test(int a,char *inp,char * outp) {
	initialize();
	ifstream input(inp);
	ofstream output(outp);
	//scanf("%d", &n);
	//name[1] = p[ioIndex++];
	input  >> name[1];
	num[name[1]] = 1;
	root = 1;
	T = 1;
	for (int i = 1; i < a; i++) {
		int x, y;
		//st = p[ioIndex++];
		input >> st;
	

		if (num.find(st) == num.end()) {
			name[id] = st;
			num[st] = id++;
		}
		x = num[st];

		//st = p[ioIndex++]; 
		input >> st;
		

		if (num.find(st) == num.end()) {
			name[id] = st;
			num[st] = id++;
		}
		y = num[st];
		add(x, y);//i+1�ĸ�����x
		add(y, x);
	}
	dp(root);
	output << d[root]+1 <<endl;
	int x = root;
	output << name[root] << endl;
	while (son[x] != 0) {
		x = son[x];
		output << name[x] << endl;
	}
	input.close();
	output << flush; output.close(); 
}

int main()
{
	return 0;
}

